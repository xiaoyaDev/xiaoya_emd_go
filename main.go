package main

import (
	"bufio"
	"compress/gzip"
	"container/ring"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// DNSType 定义 DNS 类型
type DNSType string

const (
	DNSTypeDoH DNSType = "doh"
	DNSTypeDoT DNSType = "dot"
)

// Config 定义程序的配置文件结构
type Config struct {
	SPathsAll             []string             `json:"sPathsAll"`
	SPool                 []string             `json:"sPool"`
	ActivePaths           []string             `json:"activePaths"`
	Interval              int                  `json:"interval"`
	ScanListTime          time.Time            `json:"scanListTime"`
	ForceTimestampCheck   bool                 `json:"forceTimestampCheck"`
	PathCheckTimestamps   map[string]time.Time `json:"pathCheckTimestamps"`
	DNSType               DNSType              `json:"dnsType"`
	DNSServer             string               `json:"dnsServer"`
	DNSEnabled            bool                 `json:"dnsEnabled"`
	LogSize               int                  `json:"logSize"`
	BandwidthLimitEnabled bool                 `json:"bandwidthLimitEnabled"`
	BandwidthLimitMBps    float64              `json:"bandwidthLimitMBps"`
	MaxConcurrency        int                  `json:"maxConcurrency"`
	PathUpdateNotices     map[string]bool      `json:"pathUpdateNotices"`
}

// LogEntry 定义日志条目结构
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Message   string `json:"message"`
}

// SyncState 定义同步状态结构
type SyncState struct {
	Running      bool
	Trigger      chan struct{}
	LastStart    time.Time
	CheckingPath string
}

// ServerInfo 定义服务器信息结构
type ServerInfo struct {
	URL          string
	ResponseTime time.Duration
}

// FileInfo 定义文件信息结构
type FileInfo struct {
	Path      string
	Timestamp int64
}

// 全局变量
var (
	config      Config
	configMu    sync.RWMutex
	httpClient  *http.Client
	logs        *ring.Ring
	logsMu      sync.Mutex
	syncState   = SyncState{Running: true, Trigger: make(chan struct{}, 1)}
	syncStateMu sync.Mutex
)

// CustomResolver 自定义 DNS 解析器
type CustomResolver struct {
	Type       DNSType
	Server     string
	HTTPClient *http.Client
}

func (r *CustomResolver) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	server := r.Server
	if r.Type == DNSTypeDoH {
		if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
			server = "https://" + server
		}
		if !strings.HasSuffix(server, "/dns-query") {
			server += "/dns-query"
		}
		data, err := msg.Pack()
		if err != nil {
			return nil, err
		}
		resp, err := r.HTTPClient.Post(server, "application/dns-message", strings.NewReader(string(data)))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var reply dns.Msg
		if err := reply.Unpack(body); err != nil {
			return nil, err
		}
		return extractIPs(&reply), nil
	} else if r.Type == DNSTypeDoT {
		if strings.Contains(server, "://") {
			server = strings.SplitN(server, "://", 2)[1]
		}
		if !strings.Contains(server, ":") {
			server += ":853"
		}
		conn, err := tls.Dial("tcp", server, &tls.Config{
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		dnsConn := &dns.Conn{Conn: conn}
		if err := dnsConn.WriteMsg(msg); err != nil {
			return nil, err
		}
		reply, err := dnsConn.ReadMsg()
		if err != nil {
			return nil, err
		}
		return extractIPs(reply), nil
	}
	return net.DefaultResolver.LookupHost(ctx, hostname)
}

func extractIPs(msg *dns.Msg) []string {
	var ips []string
	for _, ans := range msg.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}

// CustomDialer 使用自定义 DNS 解析
type CustomDialer struct {
	Resolver *CustomResolver
}

func (d *CustomDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := d.Resolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
}

// testDNS 测试 DNS 解析能力并返回可用模式
func testDNS(resolver *CustomResolver, defaultType DNSType) (DNSType, error) {
	testDomains := []string{"dash.cloudflare.com", "www.bing.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var primaryType, secondaryType DNSType
	if defaultType == DNSTypeDoT {
		primaryType = DNSTypeDoT
		secondaryType = DNSTypeDoH
	} else {
		primaryType = DNSTypeDoH
		secondaryType = DNSTypeDoT
	}

	resolver.Type = primaryType
	addLog("info", fmt.Sprintf("测试 %s 解析 (服务器: %s)", primaryType, resolver.Server))
	primarySuccess := true
	for _, domain := range testDomains {
		ips, err := resolver.LookupHost(ctx, domain)
		if err != nil || len(ips) == 0 {
			addLog("warning", fmt.Sprintf("%s 解析 %s 失败: %v", primaryType, domain, err))
			primarySuccess = false
			break
		}
		addLog("info", fmt.Sprintf("%s 解析 %s 成功: %v", primaryType, domain, ips))
	}
	if primarySuccess {
		return primaryType, nil
	}

	resolver.Type = secondaryType
	addLog("info", fmt.Sprintf("主模式 %s 失败，测试 %s 解析 (服务器: %s)", primaryType, secondaryType, resolver.Server))
	secondarySuccess := true
	for _, domain := range testDomains {
		ips, err := resolver.LookupHost(ctx, domain)
		if err != nil || len(ips) == 0 {
			addLog("warning", fmt.Sprintf("%s 解析 %s 失败: %v", secondaryType, domain, err))
			secondarySuccess = false
			break
		}
		addLog("info", fmt.Sprintf("%s 解析 %s 成功: %v", secondaryType, domain, ips))
	}
	if secondarySuccess {
		return secondaryType, nil
	}

	addLog("info", "自定义 DNS 不可用，测试本地 DNS")
	localSuccess := true
	for _, domain := range testDomains {
		ips, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err != nil || len(ips) == 0 {
			addLog("warning", fmt.Sprintf("本地 DNS 解析 %s 失败: %v", domain, err))
			localSuccess = false
			break
		}
		addLog("info", fmt.Sprintf("本地 DNS 解析 %s 成功: %v", domain, ips))
	}
	if localSuccess {
		return "", nil
	}

	return "", fmt.Errorf("所有 DNS 模式均不可用")
}

// initHttpClient 初始化 HTTP 客户端
func initHttpClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	addLog("info", "开始初始化 HTTP 客户端")
	configMu.RLock()
	dnsEnabled := config.DNSEnabled
	dnsType := config.DNSType
	dnsServer := config.DNSServer
	bandwidthLimitEnabled := config.BandwidthLimitEnabled
	bandwidthLimitMBps := config.BandwidthLimitMBps
	configMu.RUnlock()

	if dnsEnabled {
		dohClient := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
		resolver := &CustomResolver{
			Type:       dnsType,
			Server:     dnsServer,
			HTTPClient: dohClient,
		}
		addLog("info", fmt.Sprintf("开始测试自定义 DNS (%s: %s)", dnsType, dnsServer))
		testedType, err := testDNS(resolver, dnsType)
		configMu.Lock()
		if err != nil {
			addLog("warning", "所有 DNS 模式测试失败，将使用系统默认 DNS")
			config.DNSEnabled = false
		} else if testedType == "" {
			addLog("info", "自定义 DNS 不可用，使用系统默认 DNS")
			config.DNSEnabled = false
		} else {
			config.DNSType = testedType
			resolver.Type = testedType
			transport.DialContext = (&CustomDialer{Resolver: resolver}).DialContext
			addLog("success", fmt.Sprintf("DNS 配置生效: %s (服务器: %s)", config.DNSType, config.DNSServer))
		}
		configMu.Unlock()
	} else {
		addLog("info", "自定义 DNS 未启用，使用系统默认 DNS")
		transport.DialContext = nil
	}

	var finalTransport http.RoundTripper = transport
	if bandwidthLimitEnabled {
		// MB/s 转换为 bytes/s
		bytesPerSecond := bandwidthLimitMBps * 1024 * 1024
		limiter := rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond))
		finalTransport = &limitedTransport{
			limiter:      limiter,
			roundTripper: transport,
		}
		addLog("info", fmt.Sprintf("带宽限制启用: %.2f MB/s", bandwidthLimitMBps))
	} else {
		addLog("info", "带宽限制未启用")
	}

	httpClient = &http.Client{
		Timeout:   15 * time.Second,
		Transport: finalTransport,
	}
	addLog("info", "HTTP 客户端初始化完成")
}

// limitedTransport 实现带宽限制的 Transport
type limitedTransport struct {
	limiter      *rate.Limiter
	roundTripper http.RoundTripper
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.roundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedReader{
		reader:  resp.Body,
		limiter: t.limiter,
		ctx:     req.Context(),
	}
	return resp, nil
}

// limitedReader 限制读取速度的 io.ReadCloser
type limitedReader struct {
	reader  io.ReadCloser
	limiter *rate.Limiter
	ctx     context.Context
}

func (r *limitedReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if err != nil {
		return n, err
	}
	err = r.limiter.WaitN(r.ctx, n)
	return n, err
}

func (r *limitedReader) Close() error {
	return r.reader.Close()
}

// addLog 添加日志到环形缓冲区
func addLog(logType, message string) {
	logsMu.Lock()
	defer logsMu.Unlock()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logs.Value = LogEntry{Timestamp: timestamp, Type: logType, Message: message}
	logs = logs.Next()
}

// getLogs 获取日志条目，支持分页和搜索
func getLogs(limit, page int, filter, search string) ([]LogEntry, int) {
	logsMu.Lock()
	defer logsMu.Unlock()

	allLogs := make([]LogEntry, 0, config.LogSize)
	r := logs
	for i := 0; i < config.LogSize; i++ {
		if r.Value != nil {
			allLogs = append(allLogs, r.Value.(LogEntry))
		}
		r = r.Next()
	}

	if len(allLogs) == 0 {
		return []LogEntry{}, 0
	}

	sort.Slice(allLogs, func(i, j int) bool {
		return allLogs[i].Timestamp < allLogs[j].Timestamp
	})

	var filteredLogs []LogEntry
	if filter != "" {
		for _, log := range allLogs {
			if log.Type == filter {
				filteredLogs = append(filteredLogs, log)
			}
		}
	} else {
		filteredLogs = allLogs
	}

	if search != "" {
		search = strings.ToLower(search)
		var searchedLogs []LogEntry
		for _, log := range filteredLogs {
			if strings.Contains(strings.ToLower(log.Message), search) ||
				strings.Contains(strings.ToLower(log.Timestamp), search) ||
				strings.Contains(strings.ToLower(log.Type), search) {
				searchedLogs = append(searchedLogs, log)
			}
		}
		filteredLogs = searchedLogs
	}

	total := len(filteredLogs)
	if total == 0 {
		return []LogEntry{}, 0
	}

	start := (page - 1) * limit
	if start >= total {
		return []LogEntry{}, total
	}
	end := start + limit
	if end > total {
		end = total
	}

	return filteredLogs[start:end], total
}

// loadConfig 从 config.json 加载配置
func loadConfig() error {
	configFile, err := os.Open("config.json")
	if err != nil {
		configMu.Lock()
		config = Config{
			Interval:              1,
			ForceTimestampCheck:   true,
			PathCheckTimestamps:   make(map[string]time.Time),
			DNSType:               DNSTypeDoH,
			DNSServer:             "https://1.1.1.1/dns-query",
			DNSEnabled:            true,
			LogSize:               1000,
			BandwidthLimitEnabled: false,
			BandwidthLimitMBps:    5.0,
			MaxConcurrency:        500,
			PathUpdateNotices:     make(map[string]bool),
		}
		configMu.Unlock()
		addLog("info", "配置文件未找到，已创建默认配置")
		return saveConfig()
	}
	defer configFile.Close()

	var newConfig Config
	err = json.NewDecoder(configFile).Decode(&newConfig)
	if err != nil {
		return err
	}

	if newConfig.LogSize <= 0 {
		newConfig.LogSize = 1000
	}
	if newConfig.Interval <= 0 {
		newConfig.Interval = 1
	}
	if newConfig.MaxConcurrency <= 0 {
		newConfig.MaxConcurrency = 500
	}
	if newConfig.PathCheckTimestamps == nil {
		newConfig.PathCheckTimestamps = make(map[string]time.Time)
	}
	if newConfig.PathUpdateNotices == nil {
		newConfig.PathUpdateNotices = make(map[string]bool)
	}

	logsMu.Lock()
	currentSize := logs.Len()
	if currentSize != newConfig.LogSize {
		logsMu.Unlock()
		oldLogs, _ := getLogs(currentSize, 1, "", "")
		logsMu.Lock()
		newLogs := ring.New(newConfig.LogSize)
		for i := 0; i < len(oldLogs) && i < newConfig.LogSize; i++ {
			newLogs.Value = oldLogs[len(oldLogs)-1-i]
			newLogs = newLogs.Next()
		}
		logs = newLogs
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		logs.Value = LogEntry{Timestamp: timestamp, Type: "info", Message: fmt.Sprintf("日志缓冲区大小调整为 %d", newConfig.LogSize)}
		logs = logs.Next()
	}
	logsMu.Unlock()

	configMu.Lock()
	config = newConfig
	configMu.Unlock()

	addLog("info", "配置文件加载成功")
	return nil
}

// saveConfig 保存配置到 config.json
func saveConfig() error {
	configFile, err := os.Create("config.json")
	if err != nil {
		return err
	}
	defer configFile.Close()
	encoder := json.NewEncoder(configFile)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

// cleanFileName 清理文件名中的非法字符
func cleanFileName(name string) string {
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*]`)
	return invalidChars.ReplaceAllString(name, "_")
}

// pickBestServers 选择响应最快的服务器
func pickBestServers(pool []string) []ServerInfo {
	var wg sync.WaitGroup
	serverInfos := make([]ServerInfo, len(pool))
	for i, url := range pool {
		wg.Add(1)
		go func(index int, serverURL string) {
			defer wg.Done()
			start := time.Now()
			resp, err := httpClient.Get(serverURL + "/测试/新生 (2024) - 115/tvshow.nfo")
			if err != nil || resp.StatusCode != 200 {
				serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: 0}
				return
			}
			defer resp.Body.Close()
			serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: time.Since(start)}
		}(i, url)
	}
	wg.Wait()
	var validServers []ServerInfo
	for _, info := range serverInfos {
		if info.ResponseTime > 0 {
			validServers = append(validServers, info)
		}
	}
	sort.Slice(validServers, func(i, j int) bool {
		return validServers[i].ResponseTime < validServers[j].ResponseTime
	})
	if len(validServers) > 3 {
		return validServers[:3]
	}
	return validServers
}

// checkAndUpdateScanListGz 检查并更新 .scan.list.gz 文件
func checkAndUpdateScanListGz(serverURL, localPath string) (bool, string, error) {
	resp, err := httpClient.Get(serverURL + ".scan.list.gz")
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	serverTimeStr := resp.Header.Get("Last-Modified")
	serverTime, err := time.Parse(time.RFC1123, serverTimeStr)
	if err != nil {
		serverTime = time.Now()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	hash := sha256.New()
	hash.Write(body)
	serverHash := hex.EncodeToString(hash.Sum(nil))

	// 保存旧文件的路径
	oldPath := localPath + ".old"
	if _, err := os.Stat(localPath); err == nil {
		if err := os.Rename(localPath, oldPath); err != nil {
			addLog("warning", fmt.Sprintf("保存旧 .scan.list.gz 失败：%v", err))
		}
	}

	localFile, err := os.Create(localPath)
	if err != nil {
		return false, oldPath, err
	}
	defer localFile.Close()
	if _, err := localFile.Write(body); err != nil {
		return false, oldPath, err
	}

	if err := os.Chtimes(localPath, serverTime, serverTime); err != nil {
		addLog("error", fmt.Sprintf("设置 %s 的时间戳失败：%v", localPath, err))
	}

	configMu.Lock()
	config.ScanListTime = serverTime
	configMu.Unlock()
	if err := saveConfig(); err != nil {
		addLog("error", fmt.Sprintf("更新配置文件时间戳失败：%v", err))
	}

	if _, err := os.Stat(oldPath); err == nil {
		hash = sha256.New()
		localFile, err := os.Open(oldPath)
		if err != nil {
			addLog("warning", fmt.Sprintf("读取旧 .scan.list.gz 失败：%v", err))
			return false, oldPath, nil
		}
		defer localFile.Close()
		if _, err := io.Copy(hash, localFile); err != nil {
			addLog("warning", fmt.Sprintf("计算旧 .scan.list.gz 哈希失败：%v", err))
			return false, oldPath, nil
		}
		localHash := hex.EncodeToString(hash.Sum(nil))

		localStat, err := os.Stat(oldPath)
		if err != nil {
			addLog("warning", fmt.Sprintf("获取旧 .scan.list.gz 状态失败：%v", err))
			return false, oldPath, nil
		}
		localTime := localStat.ModTime()

		timeDiff := serverTime.Sub(localTime)
		if localHash == serverHash && !config.ScanListTime.IsZero() && timeDiff.Abs() <= 10*time.Minute {
			addLog("info", "服务器数据和本地数据一致（时间戳差异在10分钟内），无需更新")
			return true, oldPath, nil
		}
	}

	addLog("info", "元数据包 文件已更新")
	return false, oldPath, nil
}

// compareScanLists 比较新旧 .scan.list.gz 的差异
func compareScanLists(oldPath, newPath string) (map[string]FileInfo, error) {
	oldFiles := make(map[string]int64)
	newFiles := make(map[string]int64)
	pattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2} /(.*)$`)

	// 读取旧文件
	if _, err := os.Stat(oldPath); err == nil {
		oldFile, err := os.Open(oldPath)
		if err != nil {
			return nil, err
		}
		defer oldFile.Close()
		gz, err := gzip.NewReader(oldFile)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		scanner := bufio.NewScanner(gz)
		for scanner.Scan() {
			line := scanner.Text()
			match := pattern.FindStringSubmatch(line)
			if match != nil {
				file := match[1]
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					timestampStr := parts[0] + " " + parts[1]
					t, err := time.Parse("2006-01-02 15:04", timestampStr)
					if err == nil {
						oldFiles[file] = t.Unix()
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	// 读取新文件
	newFile, err := os.Open(newPath)
	if err != nil {
		return nil, err
	}
	defer newFile.Close()
	gz, err := gzip.NewReader(newFile)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		line := scanner.Text()
		match := pattern.FindStringSubmatch(line)
		if match != nil {
			file := match[1]
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				timestampStr := parts[0] + " " + parts[1]
				t, err := time.Parse("2006-01-02 15:04", timestampStr)
				if err == nil {
					newFiles[file] = t.Unix()
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// 比较差异
	diffs := make(map[string]FileInfo)
	for path, timestamp := range newFiles {
		if oldTimestamp, exists := oldFiles[path]; !exists || oldTimestamp != timestamp {
			diffs[path] = FileInfo{Path: path, Timestamp: timestamp}
		}
	}
	for path := range oldFiles {
		if _, exists := newFiles[path]; !exists {
			diffs[path] = FileInfo{Path: path, Timestamp: 0} // 标记为删除
		}
	}

	return diffs, nil
}

// extractAndSplitScanList 解压并分割 .scan.list.gz 文件，支持增量更新
func extractAndSplitScanList(gzPath, listDir string, diffs map[string]FileInfo, activePaths []string) error {
	if err := os.MkdirAll(listDir, 0777); err != nil {
		addLog("error", fmt.Sprintf("创建 list 目录失败：%v", err))
		return err
	}

	if diffs == nil {
		// 全量更新
		gzFile, err := os.Open(gzPath)
		if err != nil {
			addLog("error", fmt.Sprintf("打开 元数据包 文件失败：%v", err))
			return err
		}
		defer gzFile.Close()
		gz, err := gzip.NewReader(gzFile)
		if err != nil {
			addLog("error", fmt.Sprintf("创建 gzip 读取器失败：%v", err))
			return err
		}
		defer gz.Close()
		scanner := bufio.NewScanner(gz)
		pattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2} /(.*)$`)
		fileWriters := make(map[string]*bufio.Writer)
		fileHandles := make(map[string]*os.File)
		for scanner.Scan() {
			line := scanner.Text()
			match := pattern.FindStringSubmatch(line)
			if match != nil {
				file := match[1]
				rootDir := strings.SplitN(file, "/", 2)[0]
				filePath := filepath.Join(listDir, rootDir+".list")
				writer, ok := fileWriters[rootDir]
				if !ok {
					file, err := os.Create(filePath)
					if err != nil {
						addLog("error", fmt.Sprintf("创建 %s 文件失败：%v", filePath, err))
						return err
					}
					writer = bufio.NewWriter(file)
					fileWriters[rootDir] = writer
					fileHandles[rootDir] = file
				}
				if _, err := writer.WriteString(line + "\n"); err != nil {
					addLog("error", fmt.Sprintf("写入 %s 文件失败：%v", filePath, err))
					return err
				}
			}
		}
		for rootDir, writer := range fileWriters {
			if err := writer.Flush(); err != nil {
				addLog("error", fmt.Sprintf("刷新 %s 文件写入器失败：%v", rootDir+".list", err))
				return err
			}
			if err := fileHandles[rootDir].Close(); err != nil {
				addLog("error", fmt.Sprintf("关闭 %s 文件句柄失败：%v", rootDir+".list", err))
				return err
			}
		}
		return scanner.Err()
	}

	// 增量更新
	fileWriters := make(map[string]*bufio.Writer)
	fileHandles := make(map[string]*os.File)

	for path, info := range diffs {
		rootDir := strings.SplitN(path, "/", 2)[0]
		filePath := filepath.Join(listDir, rootDir+".list")
		writer, ok := fileWriters[rootDir]
		if !ok {
			var file *os.File
			var err error
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				file, err = os.Create(filePath)
			} else {
				file, err = os.OpenFile(filePath, os.O_RDWR|os.O_APPEND, 0666)
			}
			if err != nil {
				addLog("error", fmt.Sprintf("打开或创建 %s 文件失败：%v", filePath, err))
				return err
			}
			writer = bufio.NewWriter(file)
			fileWriters[rootDir] = writer
			fileHandles[rootDir] = file
		}
		if info.Timestamp != 0 { // 新增或更新文件
			t := time.Unix(info.Timestamp, 0)
			line := fmt.Sprintf("%s /%s\n", t.Format("2006-01-02 15:04"), path)
			if _, err := writer.WriteString(line); err != nil {
				addLog("error", fmt.Sprintf("写入 %s 文件失败：%v", filePath, err))
				return err
			}
		}
	}

	for rootDir, writer := range fileWriters {
		if err := writer.Flush(); err != nil {
			addLog("error", fmt.Sprintf("刷新 %s 文件写入器失败：%v", rootDir+".list", err))
			return err
		}
		if err := fileHandles[rootDir].Close(); err != nil {
			addLog("error", fmt.Sprintf("关闭 %s 文件句柄失败：%v", rootDir+".list", err))
			return err
		}
	}

	return nil
}

// loadServerFilesFromListDir 从 list 目录加载服务器文件列表
func loadServerFilesFromListDir(listDir string, paths []string) (map[string]int64, error) {
	files := make(map[string]int64)
	for _, path := range paths {
		listPath := filepath.Join(listDir, filepath.Base(path)+".list")
		if _, err := os.Stat(listPath); os.IsNotExist(err) {
			continue
		}
		file, err := os.Open(listPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			match := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2} /(.*)$`).FindStringSubmatch(line)
			if match != nil {
				file := match[1]
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					timestampStr := parts[0] + " " + parts[1]
					t, err := time.Parse("2006-01-02 15:04", timestampStr)
					if err == nil {
						files[file] = t.Unix()
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// downloadFile 下载文件，支持动态切换服务器
func downloadFile(file FileInfo, servers []ServerInfo, media, cleanedPath string) error {
	localPath := filepath.Join(media, cleanedPath)
	need, err := needDownload(file, localPath)
	if err != nil {
		return err
	}
	if !need {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0777); err != nil {
		return fmt.Errorf("创建目录失败：%v", err)
	}
	for i, server := range servers {
		encodedUrlPath := url.PathEscape(file.Path)
		url := server.URL + "/" + encodedUrlPath
		resp, err := httpClient.Get(url)
		if err != nil {
			addLog("warning", fmt.Sprintf("从服务器 %s 下载 %s 失败：%v", server.URL, file.Path, err))
			if i < len(servers)-1 {
				addLog("info", fmt.Sprintf("尝试备用服务器 %s", servers[i+1].URL))
				continue
			}
			return fmt.Errorf("所有服务器下载 %s 失败", file.Path)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			out, err := os.Create(localPath + ".tmp")
			if err != nil {
				return fmt.Errorf("创建文件 %s 失败：%v", localPath, err)
			}
			written, err := io.Copy(out, resp.Body)
			out.Close()
			if err != nil {
				os.Remove(localPath + ".tmp")
				return fmt.Errorf("写入文件 %s 失败：%v", localPath, err)
			}
			if written == 0 {
				os.Remove(localPath + ".tmp")
				return fmt.Errorf("下载 %s 内容为空", file.Path)
			}
			if err := os.Rename(localPath+".tmp", localPath); err != nil {
				os.Remove(localPath + ".tmp")
				return fmt.Errorf("重命名文件 %s 失败：%v", localPath, err)
			}
			modTime := time.Unix(file.Timestamp, 0)
			if err := os.Chtimes(localPath, modTime, modTime); err != nil {
				addLog("error", fmt.Sprintf("设置文件 %s 的时间戳失败：%v", localPath, err))
				os.Remove(localPath)
				return err
			}
			if i == 0 {
				addLog("success", fmt.Sprintf("下载完成：%s", file.Path))
			} else {
				addLog("success", fmt.Sprintf("下载完成：%s，使用服务器：%s", file.Path, server.URL))
			}
			return nil
		}
		addLog("warning", fmt.Sprintf("服务器 %s 返回状态码 %d", server.URL, resp.StatusCode))
	}
	return fmt.Errorf("所有服务器下载 %s 失败", file.Path)
}

// needDownload 检查是否需要下载文件
func needDownload(file FileInfo, localPath string) (bool, error) {
	stat, err := os.Stat(localPath)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return true, fmt.Errorf("检查文件 %s 失败：%v", localPath, err)
	}

	localTime := stat.ModTime().Unix()
	serverTime := file.Timestamp
	timeDiff := time.Duration(serverTime-localTime) * time.Second
	if timeDiff.Abs() <= 10*time.Minute {
		return false, nil
	}
	return serverTime > localTime, nil
}

// testMediaFolder 测试并创建媒体目录
func testMediaFolder(media string, paths []string) bool {
	for _, path := range paths {
		fullPath := filepath.Join(media, path)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			if err := os.MkdirAll(fullPath, 0777); err != nil {
				addLog("error", fmt.Sprintf("创建目录 %s 失败：%v", fullPath, err))
				return false
			}
		}
	}
	return true
}

// deleteLocalExtraFiles 删除本地多余文件
func deleteLocalExtraFiles(mediaDir string, serverFiles map[string]int64, paths []string) error {
	for _, path := range paths {
		err := filepath.Walk(filepath.Join(mediaDir, path), func(localPath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				empty, err := isDirEmpty(localPath)
				if err != nil {
					return err
				}
				if empty {
					if err := os.Remove(localPath); err != nil {
						return fmt.Errorf("删除空目录 %s 失败：%v", localPath, err)
					}
					addLog("info", fmt.Sprintf("删除空目录：%s", localPath))
				}
			} else {
				relativePath, err := filepath.Rel(mediaDir, localPath)
				if err != nil {
					return err
				}
				if _, exists := serverFiles[filepath.ToSlash(relativePath)]; !exists {
					if err := os.Remove(localPath); err != nil {
						return fmt.Errorf("删除文件 %s 失败：%v", localPath, err)
					}
					addLog("info", fmt.Sprintf("删除文件：%s", localPath))
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// isDirEmpty 检查目录是否为空
func isDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err == io.EOF, err
}

// countLocalListFiles 统计 list 目录中的文件数量
func countLocalListFiles(listDir string, paths []string) (int, error) {
	var count int
	for _, path := range paths {
		listPath := filepath.Join(listDir, filepath.Base(path)+".list")
		if _, err := os.Stat(listPath); os.IsNotExist(err) {
			continue
		}
		file, err := os.Open(listPath)
		if err != nil {
			addLog("error", fmt.Sprintf("打开列表文件 %s 失败：%v", listPath, err))
			return 0, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			count++
		}
		if err := scanner.Err(); err != nil {
			return 0, err
		}
	}
	return count, nil
}

// countLocalFiles 统计本地媒体目录中的文件数量
func countLocalFiles(mediaDir string, paths []string) (int, error) {
	var count int
	for _, path := range paths {
		err := filepath.Walk(filepath.Join(mediaDir, path), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				count++
			}
			return nil
		})
		if err != nil {
			addLog("error", fmt.Sprintf("统计本地文件失败：%v", err))
			return 0, err
		}
	}
	return count, nil
}

// syncFiles 执行文件同步逻辑
func syncFiles(media *string) {
	if *media == "" {
		addLog("error", "必须提供 --media 参数")
		return
	}

	if err := loadConfig(); err != nil {
		addLog("error", fmt.Sprintf("初始加载配置文件失败：%v", err))
		return
	}

	configMu.RLock()
	interval := config.Interval
	configMu.RUnlock()
	if interval <= 0 {
		interval = 1
		addLog("warning", "同步间隔无效，强制设置为 1 小时")
		configMu.Lock()
		config.Interval = interval
		configMu.Unlock()
		if err := saveConfig(); err != nil {
			addLog("error", fmt.Sprintf("保存默认间隔失败：%v", err))
		}
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Hour)
	defer ticker.Stop()

	for {
		syncStateMu.Lock()
		if !syncState.Running {
			syncStateMu.Unlock()
			select {
			case <-syncState.Trigger:
				syncStateMu.Lock()
				syncState.Running = true
				syncStateMu.Unlock()
				addLog("info", "手动启动同步，开始新一轮同步")
			case <-time.After(1 * time.Second):
				continue
			}
			continue
		}
		syncState.LastStart = time.Now()
		syncStateMu.Unlock()

		startTime := time.Now()
		configMu.RLock()
		paths := config.ActivePaths
		if len(paths) == 0 {
			paths = config.SPathsAll
		}
		maxConcurrency := config.MaxConcurrency
		configMu.RUnlock()
		addLog("info", fmt.Sprintf("同步路径：%v", paths))
		mediaDir := filepath.Clean(*media)
		if !testMediaFolder(mediaDir, paths) {
			addLog("warning", fmt.Sprintf("%s 不包含所有目标文件夹，将创建缺失的目录", mediaDir))
		}
		configMu.RLock()
		servers := pickBestServers(config.SPool)
		configMu.RUnlock()
		if len(servers) == 0 {
			addLog("error", "没有可用的服务器，等待 5 分钟后重试")
			time.Sleep(5 * time.Minute)
			continue
		}
		url := servers[0].URL
		addLog("info", fmt.Sprintf("使用服务器：%s", url))
		currentDir, _ := os.Getwd()
		localListDir := filepath.Join(currentDir, "list")
		scanListGzPath := filepath.Join(mediaDir, ".scan.list.gz")
		isSame, oldPath, err := checkAndUpdateScanListGz(url, scanListGzPath)
		if err != nil {
			addLog("error", fmt.Sprintf("检查并更新 元数据包 失败：%v", err))
			continue
		}

		var diffs map[string]FileInfo
		if !isSame && oldPath != "" {
			diffs, err = compareScanLists(oldPath, scanListGzPath)
			if err != nil {
				addLog("error", fmt.Sprintf("比较新旧 .scan.list.gz 失败：%v", err))
				continue
			}
			// 更新 PathUpdateNotices
			configMu.Lock()
			if config.PathUpdateNotices == nil {
				config.PathUpdateNotices = make(map[string]bool)
			}
			for path := range diffs {
				rootDir := strings.SplitN(path, "/", 2)[0]
				for _, p := range config.SPathsAll {
					if p == rootDir && !contains(paths, p) {
						config.PathUpdateNotices[p] = true
					}
				}
			}
			saveConfig()
			configMu.Unlock()
		}

		if isSame {
			serverFilesCount, err := countLocalListFiles(localListDir, paths)
			if err != nil {
				continue
			}
			localFilesCount, err := countLocalFiles(mediaDir, paths)
			if err != nil {
				continue
			}
			configMu.RLock()
			forceCheck := config.ForceTimestampCheck
			configMu.RUnlock()
			if serverFilesCount == localFilesCount && !forceCheck {
				configMu.RLock()
				nextRun := time.Now().Add(time.Duration(config.Interval) * time.Hour)
				configMu.RUnlock()
				addLog("info", fmt.Sprintf("服务器文件总数和本地文件总数一致，等待下次检测，下次时间：%s", nextRun.Format("2006-01-02 15:04:05")))
				syncStateMu.Lock()
				running := syncState.Running
				syncStateMu.Unlock()
				if running {
					select {
					case <-syncState.Trigger:
						addLog("info", "手动触发同步，跳过等待")
					case <-ticker.C:
						addLog("info", "定时器触发，进入下一次同步")
					case <-time.After(time.Duration(interval) * time.Hour):
						addLog("warning", "同步超时，强制进入下一次循环")
					}
				}
				continue
			}
		}

		addLog("info", fmt.Sprintf("开始解压并分割 元数据包 文件到 %s", localListDir))
		if err := extractAndSplitScanList(scanListGzPath, localListDir, diffs, paths); err != nil {
			addLog("error", fmt.Sprintf("解压并分割 元数据包 失败：%v", err))
			continue
		}
		addLog("success", fmt.Sprintf("成功解压并分割 元数据包 文件到 %s", localListDir))

		for _, path := range paths {
			serverFiles, err := loadServerFilesFromListDir(localListDir, []string{path})
			if err != nil {
				addLog("error", fmt.Sprintf("加载服务器文件列表失败：%v", err))
				continue
			}
			localListCount, err := countLocalListFiles(localListDir, []string{path})
			if err != nil {
				continue
			}
			localFilesCount, err := countLocalFiles(mediaDir, []string{path})
			if err != nil {
				continue
			}
			addLog("info", fmt.Sprintf("目录 %s：服务器文件数量：%d，本地文件数量：%d", path, localListCount, localFilesCount))
			if err := deleteLocalExtraFiles(mediaDir, serverFiles, []string{path}); err != nil {
				addLog("error", fmt.Sprintf("删除本地多余文件失败：%v", err))
				continue
			}
			var wg sync.WaitGroup
			semaphore := make(chan struct{}, maxConcurrency)
			for filePath, timestamp := range serverFiles {
				if diffs != nil {
					if diffInfo, exists := diffs[filePath]; !exists || diffInfo.Timestamp == 0 {
						continue // 跳过无差异或已删除的文件
					}
				}
				wg.Add(1)
				go func(p string, t int64) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()
					cleanedPath := filepath.Join(filepath.Dir(p), cleanFileName(filepath.Base(p)))
					fileInfo := FileInfo{Path: p, Timestamp: t}
					if err := downloadFile(fileInfo, servers, mediaDir, cleanedPath); err != nil {
						addLog("error", fmt.Sprintf("下载 %s 失败：%v", p, err))
					}
				}(filePath, timestamp)
			}
			wg.Wait()
			localListCountAfter, err := countLocalListFiles(localListDir, []string{path})
			if err != nil {
				continue
			}
			localFilesCountAfter, err := countLocalFiles(mediaDir, []string{path})
			if err != nil {
				continue
			}
			addLog("info", fmt.Sprintf("目录 %s：同步后服务器文件数量：%d，本地文件数量：%d", path, localListCountAfter, localFilesCountAfter))
		}

		syncStateMu.Lock()
		if syncState.Running {
			addLog("success", fmt.Sprintf("所有目录同步完成，程序运行时间：%s", time.Since(startTime)))
			configMu.RLock()
			nextRun := time.Now().Add(time.Duration(config.Interval) * time.Hour)
			configMu.RUnlock()
			addLog("info", fmt.Sprintf("同步完成，进入等待状态，下次检测时间：%s", nextRun.Format("2006-01-02 15:04:05")))
			syncState.LastStart = time.Now()
		}
		syncStateMu.Unlock()

		syncStateMu.Lock()
		running := syncState.Running
		syncStateMu.Unlock()
		if running {
			configMu.RLock()
			interval = config.Interval
			configMu.RUnlock()
			select {
			case <-syncState.Trigger:
				addLog("info", "手动触发同步，跳过等待")
			case <-ticker.C:
				addLog("info", "定时器触发，进入下一次同步")
			case <-time.After(time.Duration(interval) * time.Hour):
				addLog("warning", "同步超时，强制进入下一次循环")
			}
		}
	}
}

// contains 检查字符串是否在切片中
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// handleConfig 处理配置更新请求
func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var newConfig struct {
		SPathsAll             *[]string `json:"sPathsAll,omitempty"`
		SPool                 *[]string `json:"sPool,omitempty"`
		ActivePaths           *[]string `json:"activePaths,omitempty"`
		Interval              *int      `json:"interval,omitempty"`
		ForceTimestampCheck   *bool     `json:"forceTimestampCheck,omitempty"`
		DNSType               *DNSType  `json:"dnsType,omitempty"`
		DNSServer             *string   `json:"dnsServer,omitempty"`
		DNSEnabled            *bool     `json:"dnsEnabled,omitempty"`
		LogSize               *int      `json:"logSize,omitempty"`
		BandwidthLimitEnabled *bool     `json:"bandwidthLimitEnabled,omitempty"`
		BandwidthLimitMBps    *float64  `json:"bandwidthLimitMBps,omitempty"`
		MaxConcurrency        *int      `json:"maxConcurrency,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "解析JSON数据失败", http.StatusBadRequest)
		return
	}
	if newConfig.SPathsAll == nil && newConfig.SPool == nil && newConfig.ActivePaths == nil && newConfig.Interval == nil && newConfig.ForceTimestampCheck == nil && newConfig.DNSType == nil && newConfig.DNSServer == nil && newConfig.DNSEnabled == nil && newConfig.LogSize == nil && newConfig.BandwidthLimitEnabled == nil && newConfig.BandwidthLimitMBps == nil && newConfig.MaxConcurrency == nil {
		http.Error(w, "至少需要提供一个配置字段", http.StatusBadRequest)
		return
	}

	dnsChanged := false
	bandwidthChanged := false
	configMu.Lock()
	if newConfig.SPathsAll != nil {
		config.SPathsAll = *newConfig.SPathsAll
	}
	if newConfig.SPool != nil {
		if len(*newConfig.SPool) == 0 {
			configMu.Unlock()
			http.Error(w, "服务器列表不能为空", http.StatusBadRequest)
			return
		}
		config.SPool = *newConfig.SPool
		addLog("info", fmt.Sprintf("服务器地址保存成功，共 %d 个", len(config.SPool)))
	}
	if newConfig.ActivePaths != nil {
		config.ActivePaths = *newConfig.ActivePaths
		addLog("info", fmt.Sprintf("同步目录保存成功，共 %d 个", len(config.ActivePaths)))
	}
	if newConfig.Interval != nil {
		if *newConfig.Interval <= 0 || *newConfig.Interval > 24 {
			configMu.Unlock()
			http.Error(w, "同步间隔必须为 1-24 的正整数", http.StatusBadRequest)
			return
		}
		config.Interval = *newConfig.Interval
		addLog("info", fmt.Sprintf("同步间隔更新为 %d 小时", config.Interval))
	}
	if newConfig.ForceTimestampCheck != nil {
		config.ForceTimestampCheck = *newConfig.ForceTimestampCheck
		addLog("info", fmt.Sprintf("强制时间戳检查设置为 %v", config.ForceTimestampCheck))
	}
	if newConfig.DNSType != nil || newConfig.DNSServer != nil || newConfig.DNSEnabled != nil {
		dnsEnabled := config.DNSEnabled
		if newConfig.DNSEnabled != nil {
			dnsEnabled = *newConfig.DNSEnabled
		}
		dnsType := config.DNSType
		if newConfig.DNSType != nil {
			dnsType = *newConfig.DNSType
			if dnsType != DNSTypeDoH && dnsType != DNSTypeDoT {
				configMu.Unlock()
				http.Error(w, "DNS 类型必须为 'doh' 或 'dot'", http.StatusBadRequest)
				return
			}
		}
		dnsServer := config.DNSServer
		if newConfig.DNSServer != nil {
			dnsServer = *newConfig.DNSServer
		}
		if dnsEnabled {
			if dnsServer == "" {
				configMu.Unlock()
				http.Error(w, "DNS 服务器地址不能为空", http.StatusBadRequest)
				return
			}
			if dnsType == DNSTypeDoH {
				if !strings.HasPrefix(dnsServer, "http://") && !strings.HasPrefix(dnsServer, "https://") && !strings.Contains(dnsServer, "/dns-query") {
					configMu.Unlock()
					http.Error(w, "DoH 服务器需以 http:// 或 https:// 开头，或包含 /dns-query", http.StatusBadRequest)
					return
				}
			} else if dnsType == DNSTypeDoT {
				if !regexp.MustCompile(`^[\w.-]+(:[0-9]+)?$`).MatchString(dnsServer) {
					configMu.Unlock()
					http.Error(w, "DoT 服务器需为有效域名或 IP 地址，可选端口号（如 :853）", http.StatusBadRequest)
					return
				}
			}
		}
		config.DNSType = dnsType
		config.DNSServer = dnsServer
		config.DNSEnabled = dnsEnabled
		dnsChanged = true
	}
	if newConfig.LogSize != nil {
		if *newConfig.LogSize <= 0 {
			configMu.Unlock()
			http.Error(w, "日志大小必须为正整数", http.StatusBadRequest)
			return
		}
		oldLogs, _ := getLogs(config.LogSize, 1, "", "")
		config.LogSize = *newConfig.LogSize
		logsMu.Lock()
		logs = ring.New(config.LogSize)
		for i := 0; i < len(oldLogs) && i < config.LogSize; i++ {
			logs.Value = oldLogs[len(oldLogs)-1-i]
			logs = logs.Next()
		}
		logsMu.Unlock()
		addLog("info", fmt.Sprintf("日志缓冲区大小更新为 %d", config.LogSize))
	}
	if newConfig.BandwidthLimitEnabled != nil {
		config.BandwidthLimitEnabled = *newConfig.BandwidthLimitEnabled
		bandwidthChanged = true
		addLog("info", fmt.Sprintf("带宽限制已设置为 %v", config.BandwidthLimitEnabled))
	}
	if newConfig.BandwidthLimitMBps != nil {
		if *newConfig.BandwidthLimitMBps <= 0 {
			configMu.Unlock()
			http.Error(w, "带宽限制必须为正数", http.StatusBadRequest)
			return
		}
		config.BandwidthLimitMBps = *newConfig.BandwidthLimitMBps
		bandwidthChanged = true
		addLog("info", fmt.Sprintf("带宽限制值更新为 %.2f MB/s", config.BandwidthLimitMBps))
	}
	if newConfig.MaxConcurrency != nil {
		if *newConfig.MaxConcurrency <= 0 {
			configMu.Unlock()
			http.Error(w, "最大并发数必须为正整数", http.StatusBadRequest)
			return
		}
		config.MaxConcurrency = *newConfig.MaxConcurrency
		addLog("info", fmt.Sprintf("最大并发数更新为 %d", config.MaxConcurrency))
	}
	configMu.Unlock()

	if dnsChanged || bandwidthChanged {
		addLog("info", "网络配置已变更，开始重新初始化 HTTP 客户端")
		initHttpClient()
	}
	if err := saveConfig(); err != nil {
		http.Error(w, "保存配置文件失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(config)
}

// handlePaths 返回所有路径和激活路径
func handlePaths(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	configMu.RLock()
	defer configMu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"allPaths":          config.SPathsAll,
		"activePaths":       config.ActivePaths,
		"pathUpdateNotices": config.PathUpdateNotices,
	})
}

// handlePathsCount 返回本地路径的文件数量
func handlePathsCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mediaDir := flag.Lookup("media").Value.String()
	pathCounts := make(map[string]int)
	for _, path := range config.SPathsAll {
		count, err := countLocalFiles(mediaDir, []string{path})
		if err != nil {
			pathCounts[path] = -1
		} else {
			pathCounts[path] = count
		}
	}
	json.NewEncoder(w).Encode(pathCounts)
}

// handleServerPathsCount 返回服务器路径的文件数量
func handleServerPathsCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	listDir := "list"
	serverCounts := make(map[string]int)
	for _, path := range config.SPathsAll {
		count, err := countLocalListFiles(listDir, []string{path})
		if err != nil {
			serverCounts[path] = -1
		} else {
			serverCounts[path] = count
		}
	}
	json.NewEncoder(w).Encode(serverCounts)
}

// handleServers 返回服务器地址池
func handleServers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config.SPool)
}

// handleLogs 返回最近的日志
func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	limitStr := r.URL.Query().Get("limit")
	pageStr := r.URL.Query().Get("page")
	filter := r.URL.Query().Get("filter")
	search := r.URL.Query().Get("search")
	action := r.URL.Query().Get("action")

	limit := 100
	if limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}
	if limit <= 0 || limit > config.LogSize {
		limit = config.LogSize
	}

	page := 1
	if pageStr != "" {
		fmt.Sscanf(pageStr, "%d", &page)
	}
	if page <= 0 {
		page = 1
	}

	if action == "export" {
		logs, _ := getLogs(config.LogSize, 1, "", "")
		w.Header().Set("Content-Disposition", "attachment; filename=logs.json")
		json.NewEncoder(w).Encode(logs)
		return
	} else if action == "clear" {
		logsMu.Lock()
		logs = ring.New(config.LogSize)
		logsMu.Unlock()
		addLog("info", "日志已清空")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	logsData, total := getLogs(limit, page, filter, search)

	estimatedMemory := config.LogSize * 50
	var memoryStr string
	if estimatedMemory >= 1024*1024 {
		memoryStr = fmt.Sprintf("%.2f MB", float64(estimatedMemory)/(1024*1024))
	} else if estimatedMemory >= 1024 {
		memoryStr = fmt.Sprintf("%.2f KB", float64(estimatedMemory)/1024)
	} else {
		memoryStr = fmt.Sprintf("%d B", estimatedMemory)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":            logsData,
		"total":           total,
		"currentPage":     page,
		"pageSize":        limit,
		"logBufferSize":   config.LogSize,
		"estimatedMemory": memoryStr,
	})
}

// handleSync 返回同步状态
func handleSync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	nextRun := ""
	if !syncState.LastStart.IsZero() {
		nextRun = syncState.LastStart.Add(time.Duration(config.Interval) * time.Hour).Format("2006-01-02 15:04:05")
	}
	message := "同步 " + map[bool]string{true: "运行中", false: "已停止"}[syncState.Running]
	if syncState.CheckingPath != "" {
		message = fmt.Sprintf("校验目录 %s 的时间戳", syncState.CheckingPath)
	}
	json.NewEncoder(w).Encode(struct {
		IsRunning    bool   `json:"isRunning"`
		CheckingPath string `json:"checkingPath"`
		Message      string `json:"message"`
		NextRun      string `json:"nextRun"`
		Interval     int    `json:"interval"`
	}{
		IsRunning:    syncState.Running,
		CheckingPath: syncState.CheckingPath,
		Message:      message,
		NextRun:      nextRun,
		Interval:     config.Interval,
	})
}

// handleSyncStart 启动同步
func handleSyncStart(w http.ResponseWriter, r *http.Request) {
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	if syncState.Running {
		addLog("info", "同步已在运行中，手动触发新一轮同步")
	} else {
		syncState.Running = true
		addLog("info", "手动启动同步，开始新一轮同步")
	}
	syncState.Trigger <- struct{}{}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleSyncStop 停止同步
func handleSyncStop(w http.ResponseWriter, r *http.Request) {
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	if syncState.Running {
		syncState.Running = false
		addLog("info", "手动停止同步")
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleConfigGet 返回当前配置
func handleConfigGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	configMu.RLock()
	defer configMu.RUnlock()
	json.NewEncoder(w).Encode(config)
}

// handleCheckTimestamp 校验时间戳
func handleCheckTimestamp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "解析JSON数据失败", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		http.Error(w, "路径不能为空", http.StatusBadRequest)
		return
	}

	syncStateMu.Lock()
	if syncState.Running || syncState.CheckingPath != "" {
		syncStateMu.Unlock()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "busy"})
		return
	}
	syncState.CheckingPath = req.Path
	syncStateMu.Unlock()

	defer func() {
		syncStateMu.Lock()
		syncState.CheckingPath = ""
		syncStateMu.Unlock()
	}()

	mediaDir := flag.Lookup("media").Value.String()
	if mediaDir == "" {
		addLog("error", "未提供 --media 参数")
		http.Error(w, "未配置媒体目录", http.StatusInternalServerError)
		return
	}

	listDir := "list"
	serverFiles, err := loadServerFilesFromListDir(listDir, []string{req.Path})
	if err != nil {
		addLog("error", fmt.Sprintf("加载服务器文件列表失败：%v", err))
		http.Error(w, "加载服务器文件列表失败", http.StatusInternalServerError)
		return
	}

	servers := pickBestServers(config.SPool)
	if len(servers) == 0 {
		addLog("error", "没有可用的服务器")
		http.Error(w, "没有可用的服务器", http.StatusInternalServerError)
		return
	}

	startTime := time.Now()
	addLog("info", fmt.Sprintf("开始校验目录 %s 的时间戳", req.Path))

	var totalFiles int
	err = filepath.Walk(filepath.Join(mediaDir, req.Path), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalFiles++
		}
		return nil
	})
	if err != nil {
		addLog("error", fmt.Sprintf("统计本地文件总数失败：%v", err))
		http.Error(w, "校验过程出错", http.StatusInternalServerError)
		return
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, config.MaxConcurrency)
	errCount := 0
	var errCountMu sync.Mutex
	processedFiles := 0
	var processedMu sync.Mutex
	lastProgress := -10

	err = filepath.Walk(filepath.Join(mediaDir, req.Path), func(localPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relativePath, err := filepath.Rel(mediaDir, localPath)
		if err != nil {
			return err
		}
		relativePath = filepath.ToSlash(relativePath)
		serverTimestamp, exists := serverFiles[relativePath]
		if !exists {
			return nil
		}

		localTimestamp := info.ModTime().Unix()
		if time.Duration(serverTimestamp-localTimestamp)*time.Second > 10*time.Minute {
			wg.Add(1)
			go func(filePath, cleanedPath string, timestamp int64) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				fileInfo := FileInfo{Path: filePath, Timestamp: timestamp}
				cleanedPath = filepath.Join(filepath.Dir(filePath), cleanFileName(filepath.Base(filePath)))
				if err := downloadFile(fileInfo, servers, mediaDir, cleanedPath); err != nil {
					errCountMu.Lock()
					errCount++
					errCountMu.Unlock()
					addLog("error", fmt.Sprintf("更新文件 %s 失败：%v", filePath, err))
				}
				processedMu.Lock()
				processedFiles++
				progress := int(float64(processedFiles) / float64(totalFiles) * 100)
				if progress >= lastProgress+10 {
					addLog("info", fmt.Sprintf("校验目录 %s 进度：%d%% (%d/%d 文件)", req.Path, progress, processedFiles, totalFiles))
					lastProgress = progress - (progress % 10)
				}
				processedMu.Unlock()
			}(relativePath, relativePath, serverTimestamp)
		} else {
			processedMu.Lock()
			processedFiles++
			progress := int(float64(processedFiles) / float64(totalFiles) * 100)
			if progress >= lastProgress+10 {
				addLog("info", fmt.Sprintf("校验目录 %s 进度：%d%% (%d/%d 文件)", req.Path, progress, processedFiles, totalFiles))
				lastProgress = progress - (progress % 10)
			}
			processedMu.Unlock()
		}
		return nil
	})

	if err != nil {
		addLog("error", fmt.Sprintf("遍历本地文件失败：%v", err))
		http.Error(w, "校验过程出错", http.StatusInternalServerError)
		return
	}

	wg.Wait()

	processedMu.Lock()
	if processedFiles == totalFiles {
		addLog("info", fmt.Sprintf("校验目录 %s 进度：100%% (%d/%d 文件)", req.Path, processedFiles, totalFiles))
	}
	processedMu.Unlock()

	syncStateMu.Lock()
	if config.PathCheckTimestamps == nil {
		config.PathCheckTimestamps = make(map[string]time.Time)
	}
	config.PathCheckTimestamps[req.Path] = time.Now()
	if err := saveConfig(); err != nil {
		addLog("error", fmt.Sprintf("保存校验时间失败：%v", err))
	}
	syncStateMu.Unlock()

	duration := time.Since(startTime)
	addLog("success", fmt.Sprintf("目录 %s 时间戳校验完成，更新 %d 个文件，失败 %d 个，耗时 %s", req.Path, len(serverFiles)-errCount, errCount, duration))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"lastCheckTime": config.PathCheckTimestamps[req.Path].Format(time.RFC3339),
	})
}

func main() {
	logs = ring.New(1000)
	err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置文件失败：%v\n", err)
		os.Exit(1)
	}

	media := flag.String("media", "", "存储下载媒体文件的路径（必须）")
	flag.Parse()

	initHttpClient()

	addLog("info", "程序初始化完成，开始后台同步")

	go syncFiles(media)

	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/api/paths", handlePaths)
	http.HandleFunc("/api/paths/count", handlePathsCount)
	http.HandleFunc("/api/server-paths-count", handleServerPathsCount)
	http.HandleFunc("/api/servers", handleServers)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/sync", handleSync)
	http.HandleFunc("/api/sync/start", handleSyncStart)
	http.HandleFunc("/api/sync/stop", handleSyncStop)
	http.HandleFunc("/api/config/get", handleConfigGet)
	http.HandleFunc("/api/check-timestamp", handleCheckTimestamp)
	http.Handle("/", http.FileServer(http.Dir(".")))

	addLog("info", "服务器启动，监听端口 :8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		addLog("error", fmt.Sprintf("服务器启动失败：%v", err))
		os.Exit(1)
	}
}
