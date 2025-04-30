package main

import (
	"bufio"
	"compress/gzip"
	"container/ring"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
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
	DNSTypeDoH         DNSType = "doh"
	DNSTypeDoT         DNSType = "dot"
	TimeFormatStandard         = "2006-01-02 15:04:05.000" // 标准时间格式，带毫秒
)

// Config 定义程序的配置文件结构
type Config struct {
	SPathsAll             []string        `json:"sPathsAll"`
	SPool                 []string        `json:"sPool"`
	ActivePaths           []string        `json:"activePaths"`
	Interval              int             `json:"interval"`
	ScanListTime          time.Time       `json:"scanListTime"`
	DNSType               DNSType         `json:"dnsType"`
	DNSServer             string          `json:"dnsServer"`
	DNSEnabled            bool            `json:"dnsEnabled"`
	LogSize               int             `json:"logSize"`
	BandwidthLimitEnabled bool            `json:"bandwidthLimitEnabled"`
	BandwidthLimitMBps    float64         `json:"bandwidthLimitMBps"`
	MaxConcurrency        int             `json:"maxConcurrency"`
	PathUpdateNotices     map[string]bool `json:"pathUpdateNotices"`
	ServerPathCounts      map[string]int  `json:"serverPathCounts"`
	LocalPathCounts       map[string]int  `json:"localPathCounts"`
}

// LogEntry 定义日志条目结构
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	NanoTime  int64  `json:"-"` // 排序用，纳秒级
	Type      string `json:"type"`
	Message   string `json:"message"`
}

// SyncState 定义同步状态结构
type SyncState struct {
	Running   bool
	Trigger   chan struct{}
	LastStart time.Time
	SyncDone  chan struct{} // 通知主同步退出
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

// FileInfoMap 定义文件信息映射类型
type FileInfoMap map[string]int64 // key: 路径, value: 时间戳

// LocalFileInfo 结构体整合路径计数等元数据
type LocalFileInfo struct {
	Files  FileInfoMap
	Counts map[string]int
}

// 全局变量
var (
	config     Config
	configMu   sync.RWMutex
	httpClient *http.Client
	logs       *ring.Ring
	logsMu     sync.Mutex
	syncState  = SyncState{
		Running:  true,
		Trigger:  make(chan struct{}, 1),
		SyncDone: make(chan struct{}),
	}
	//go:embed static/*
	staticFiles    embed.FS
	syncStateMu    sync.Mutex
	shanghaiLoc    *time.Location      // 东八区时区
	intervalChange = make(chan int, 1) // interval 变更通道
)

// CustomResolver 自定义 DNS 解析器
type CustomResolver struct {
	Type       DNSType
	Server     string
	HTTPClient *http.Client
}

// formatTime 将时间格式化为东八区
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(shanghaiLoc).Format(TimeFormatStandard)
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
	now := time.Now()
	logs.Value = LogEntry{
		Timestamp: formatTime(now),
		NanoTime:  now.UnixNano(),
		Type:      logType,
		Message:   message,
	}
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

	// 按纳秒时间戳降序排序（最新日志在前）
	sort.Slice(allLogs, func(i, j int) bool {
		return allLogs[i].NanoTime > allLogs[j].NanoTime
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
	mediaDir := flag.Lookup("media").Value.String()
	configFilePath := filepath.Join(mediaDir, "config.json")
	configFile, err := os.Open(configFilePath)
	if err != nil {
		// 检查根目录的 config.json
		rootConfigPath := "config.json"
		rootConfigFile, rootErr := os.Open(rootConfigPath)
		if rootErr == nil {
			// 根目录存在 config.json，拷贝到 mediaDir
			defer rootConfigFile.Close()
			// 确保 mediaDir 存在
			if err := os.MkdirAll(mediaDir, 0755); err != nil {
				return fmt.Errorf("创建媒体目录 %s 失败：%v", mediaDir, err)
			}
			// 读取根目录 config.json 内容
			var rootConfig Config
			if err := json.NewDecoder(rootConfigFile).Decode(&rootConfig); err != nil {
				return fmt.Errorf("解析根目录配置文件 %s 失败：%v", rootConfigPath, err)
			}
			// 初始化 LocalPathCounts
			if rootConfig.LocalPathCounts == nil {
				rootConfig.LocalPathCounts = make(map[string]int)
			}
			// 保存到 mediaDir
			configMu.Lock()
			config = rootConfig
			configMu.Unlock()
			addLog("info", fmt.Sprintf("配置文件 %s 未找到，从根目录 %s 拷贝默认配置", configFilePath, rootConfigPath))
			return saveConfig()
		}
		// 根目录也没有 config.json，创建默认配置
		configMu.Lock()
		config = Config{
			Interval:              1,
			DNSType:               DNSTypeDoH,
			DNSServer:             "https://1.1.1.1/dns-query",
			DNSEnabled:            true,
			LogSize:               1000,
			BandwidthLimitEnabled: false,
			BandwidthLimitMBps:    5.0,
			MaxConcurrency:        500,
			PathUpdateNotices:     make(map[string]bool),
			ServerPathCounts:      make(map[string]int),
			LocalPathCounts:       make(map[string]int), // 初始化 LocalPathCounts
		}
		configMu.Unlock()
		addLog("info", fmt.Sprintf("配置文件 %s 和根目录配置文件均未找到，已创建默认配置", configFilePath))
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
	if newConfig.PathUpdateNotices == nil {
		newConfig.PathUpdateNotices = make(map[string]bool)
	}
	if newConfig.ServerPathCounts == nil {
		newConfig.ServerPathCounts = make(map[string]int)
	}
	if newConfig.LocalPathCounts == nil {
		newConfig.LocalPathCounts = make(map[string]int)
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
		timestamp := formatTime(time.Now())
		logs.Value = LogEntry{Timestamp: timestamp, NanoTime: time.Now().UnixNano(), Type: "info", Message: fmt.Sprintf("日志缓冲区大小调整为 %d", newConfig.LogSize)}
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
	mediaDir := flag.Lookup("media").Value.String()
	configFilePath := filepath.Join(mediaDir, "config.json")
	configFile, err := os.Create(configFilePath)
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
	invalidChars := regexp.MustCompile(`/`)
	return invalidChars.ReplaceAllString(name, "_")
}

// pickBestServers 选择时间戳最新且响应最快的服务器，仅选择时间戳一致的备选服务器
func pickBestServers(pool []string) []ServerInfo {
	var wg sync.WaitGroup
	serverInfos := make([]ServerInfo, len(pool))
	var mu sync.Mutex
	type serverDetail struct {
		info         ServerInfo
		lastModified time.Time
	}
	details := make([]serverDetail, len(pool))

	// 并行请求所有服务器
	for i, url := range pool {
		wg.Add(1)
		go func(index int, serverURL string) {
			defer wg.Done()
			start := time.Now()
			resp, err := httpClient.Get(serverURL + "/.scan.list.gz")
			if err != nil || resp.StatusCode != 200 {
				mu.Lock()
				serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: 0}
				details[index] = serverDetail{info: serverInfos[index], lastModified: time.Time{}}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			// 解析 Last-Modified 时间戳
			lastModifiedStr := resp.Header.Get("Last-Modified")
			var lastModified time.Time
			if lastModifiedStr != "" {
				var err error
				lastModified, err = time.Parse(time.RFC1123, lastModifiedStr)
				if err != nil {
					addLog("warning", fmt.Sprintf("服务器 %s 解析 Last-Modified 失败：%v", serverURL, err))
					mu.Lock()
					serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: 0}
					details[index] = serverDetail{info: serverInfos[index], lastModified: time.Time{}}
					mu.Unlock()
					return
				}
			} else {
				addLog("warning", fmt.Sprintf("服务器 %s 未提供 Last-Modified 头", serverURL))
				mu.Lock()
				serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: 0}
				details[index] = serverDetail{info: serverInfos[index], lastModified: time.Time{}}
				mu.Unlock()
				return
			}

			responseTime := time.Since(start)
			mu.Lock()
			serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: responseTime}
			details[index] = serverDetail{info: serverInfos[index], lastModified: lastModified}
			mu.Unlock()
		}(i, url)
	}
	wg.Wait()

	// 找到最新的 Last-Modified 时间戳
	var latestTime time.Time
	for _, detail := range details {
		if !detail.lastModified.IsZero() && (latestTime.IsZero() || detail.lastModified.After(latestTime)) {
			latestTime = detail.lastModified
		}
	}

	if latestTime.IsZero() {
		addLog("error", "没有服务器提供有效的 Last-Modified 时间戳")
		return []ServerInfo{}
	}

	// 选择时间戳等于最新的服务器
	var candidates []serverDetail
	for _, detail := range details {
		if !detail.lastModified.IsZero() && detail.lastModified.Equal(latestTime) {
			candidates = append(candidates, detail)
		}
	}

	if len(candidates) == 0 {
		addLog("error", "没有服务器具有最新时间戳")
		return []ServerInfo{}
	}

	// 按响应时间排序
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].info.ResponseTime < candidates[j].info.ResponseTime
	})

	// 选择最快的主服务器，最多 2 个备选服务器（总共最多 3 个）
	result := make([]ServerInfo, 0, 3)
	for i, candidate := range candidates {
		if i >= 3 {
			break
		}
		result = append(result, candidate.info)
	}

	if len(result) == 0 {
		addLog("error", "没有可用的服务器")
		return []ServerInfo{}
	}

	// 日志记录
	addLog("info", fmt.Sprintf("选择主服务器 %s（响应时间：%s，更新时间：%s）",
		result[0].URL, result[0].ResponseTime, formatTime(latestTime)))
	if len(result) > 1 {
		addLog("info", fmt.Sprintf("备用服务器1：%s（响应时间：%s）", result[1].URL, result[1].ResponseTime))
	}
	if len(result) > 2 {
		addLog("info", fmt.Sprintf("备用服务器2：%s（响应时间：%s）", result[2].URL, result[2].ResponseTime))
	}
	if len(candidates) > 3 {
		addLog("info", fmt.Sprintf("存在更多符合条件的服务器（共 %d 个），仅选择最快的 3 个", len(candidates)))
	}

	return result
}

// handleRefreshLocal 刷新本地文件数据并更新文件数量
func handleRefreshLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	mediaDir := flag.Lookup("media").Value.String()
	configMu.RLock()
	paths := config.SPathsAll
	configMu.RUnlock()

	// 使用新的内存Map方式扫描
	localMap, err := scanLocalFilesToMap(mediaDir, paths)
	if err != nil {
		addLog("error", fmt.Sprintf("刷新本地文件映射失败：%v", err))
		http.Error(w, "刷新本地文件映射失败", http.StatusInternalServerError)
		return
	}

	// 更新配置中的路径计数
	configMu.Lock()
	if config.LocalPathCounts == nil {
		config.LocalPathCounts = make(map[string]int)
	}

	for path, count := range localMap.Counts {
		config.LocalPathCounts[path] = count
	}

	// 清理不存在的路径
	for path := range config.LocalPathCounts {
		found := false
		for _, p := range paths {
			if p == path {
				found = true
				break
			}
		}
		if !found {
			delete(config.LocalPathCounts, path)
		}
	}

	if err := saveConfig(); err != nil {
		configMu.Unlock()
		addLog("error", fmt.Sprintf("保存配置文件失败：%v", err))
		http.Error(w, "保存配置文件失败", http.StatusInternalServerError)
		return
	}
	configMu.Unlock()

	addLog("success", "本地文件数量刷新完成")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// scanLocalFilesToMap 扫描本地文件并生成文件信息Map
func scanLocalFilesToMap(mediaDir string, paths []string) (*LocalFileInfo, error) {
	startTime := time.Now()
	addLog("info", fmt.Sprintf("开始扫描 %d 个路径", len(paths)))

	result := &LocalFileInfo{
		Files:  make(FileInfoMap),
		Counts: make(map[string]int),
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 并发扫描每个路径
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			dirPath := filepath.Join(mediaDir, p)
			count := 0

			err := filepath.Walk(dirPath, func(filePath string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}

				relativePath, _ := filepath.Rel(mediaDir, filePath)
				relativePath = filepath.ToSlash(relativePath)

				mu.Lock()
				result.Files[relativePath] = info.ModTime().Unix()
				count++
				mu.Unlock()

				return nil
			})

			if err == nil {
				mu.Lock()
				result.Counts[p] = count
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()

	// 清理无效路径计数
	for path := range result.Counts {
		if !contains(paths, path) {
			delete(result.Counts, path)
		}
	}

	duration := time.Since(startTime)
	addLog("success", fmt.Sprintf("本地扫描完成，共 %d 个文件，耗时 %s",
		len(result.Files), formatDuration(duration)))
	return result, nil
}

// compareAndPrepareSync 对比内存Map和服务器Map，返回需要更新和删除的文件
func compareAndPrepareSync(localMap, serverMap FileInfoMap, paths []string) ([]FileInfo, []string, error) {
	addLog("info", "开始差异对比")

	toUpdate := make([]FileInfo, 0)
	toDelete := make([]string, 0)
	pathNotice := make(map[string]bool)

	// 检查服务器文件更新
	for path, serverTS := range serverMap {
		shouldSync := false
		for _, prefix := range paths {
			if strings.HasPrefix(path, prefix) {
				shouldSync = true
				break
			}
		}
		if !shouldSync {
			continue
		}

		localTS, exists := localMap[path]
		if !exists || serverTS-localTS > 600 { // 服务器比本地超过 10 分钟
			toUpdate = append(toUpdate, FileInfo{Path: path, Timestamp: serverTS})
		}
	}

	// 检查需要删除的文件
	for path := range localMap {
		shouldDelete := false
		for _, prefix := range paths {
			if strings.HasPrefix(path, prefix) {
				shouldDelete = true
				break
			}
		}
		if !shouldDelete {
			continue
		}

		if _, exists := serverMap[path]; !exists {
			toDelete = append(toDelete, path)
		}
	}

	// 更新路径变更通知
	for _, file := range toUpdate {
		rootDir := getRootDir(file.Path)
		if rootDir != "" && !contains(paths, rootDir) {
			pathNotice[rootDir] = true
		}
	}

	// 原子更新配置
	configMu.Lock()
	for k := range config.PathUpdateNotices {
		if !pathNotice[k] {
			delete(config.PathUpdateNotices, k)
		}
	}
	for k, v := range pathNotice {
		config.PathUpdateNotices[k] = v
	}
	saveConfig()
	configMu.Unlock()

	addLog("info", fmt.Sprintf("内存对比完成：需更新 %d 个文件，需删除 %d 个文件",
		len(toUpdate), len(toDelete)))
	return toUpdate, toDelete, nil
}

// 修改后的 downloadFile 函数，支持上下文取消
func downloadFile(ctx context.Context, file FileInfo, servers []ServerInfo, media, cleanedPath string) error {
	localPath := filepath.Join(media, cleanedPath)
	if err := os.MkdirAll(filepath.Dir(localPath), 0777); err != nil {
		return fmt.Errorf("创建目录失败：%v", err)
	}

	var attemptErrors []string
	for i, server := range servers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			encodedUrlPath := url.PathEscape(file.Path)
			url := server.URL + "/" + encodedUrlPath
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 创建请求失败：%v", server.URL, err))
				continue
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 下载失败：%v", server.URL, err))
				if i < len(servers)-1 {
					continue
				}
				return fmt.Errorf("所有服务器下载 %s 失败：%s", file.Path, strings.Join(attemptErrors, "; "))
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound { // 404
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 返回 404", server.URL))
				// 提前退出，无需尝试其他服务器
				return fmt.Errorf("文件 %s 在服务器上不存在：%s", file.Path, strings.Join(attemptErrors, "; "))
			} else if resp.StatusCode != http.StatusOK {
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 返回状态码 %d", server.URL, resp.StatusCode))
				if i < len(servers)-1 {
					continue
				}
				return fmt.Errorf("所有服务器下载 %s 失败：%s", file.Path, strings.Join(attemptErrors, "; "))
			}

			// 下载成功
			out, err := os.Create(localPath + ".tmp")
			if err != nil {
				return fmt.Errorf("创建文件 %s 失败：%v", localPath, err)
			}
			_, err = io.Copy(out, resp.Body)
			out.Close()
			if err != nil {
				os.Remove(localPath + ".tmp")
				return fmt.Errorf("写入文件 %s 失败：%v", localPath, err)
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
	}
	return fmt.Errorf("所有服务器下载 %s 失败：%s", file.Path, strings.Join(attemptErrors, "; "))
}

// deleteLocalFile 删除本地文件，移动到回收站
func deleteLocalFile(mediaDir, path string) error {
	localPath := filepath.Join(mediaDir, path)
	recycleDir := filepath.Join(mediaDir, "recycle_bin")
	recyclePath := filepath.Join(recycleDir, path)

	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		addLog("warning", fmt.Sprintf("文件 %s 不存在，跳过移动到回收站", path))
		return nil
	} else if err != nil {
		addLog("error", fmt.Sprintf("检查文件 %s 失败：%v", path, err))
		return fmt.Errorf("检查文件 %s 失败：%v", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(recyclePath), 0777); err != nil {
		addLog("error", fmt.Sprintf("创建回收站目录 %s 失败：%v", filepath.Dir(recyclePath), err))
		return fmt.Errorf("创建回收站目录失败：%v", err)
	}

	finalRecyclePath := recyclePath
	if _, err := os.Stat(recyclePath); err == nil {
		ext := filepath.Ext(path)
		base := strings.TrimSuffix(filepath.Base(path), ext)
		timestamp := time.Now().Format("20060102_150405")
		newBase := fmt.Sprintf("%s_%s%s", base, timestamp, ext)
		finalRecyclePath = filepath.Join(filepath.Dir(recyclePath), newBase)
	}

	if err := os.Rename(localPath, finalRecyclePath); err != nil {
		addLog("error", fmt.Sprintf("移动文件 %s 到回收站 %s 失败：%v", path, finalRecyclePath, err))
		return fmt.Errorf("移动文件失败：%v", err)
	}

	addLog("info", fmt.Sprintf("文件 %s 已移动到回收站 %s", path, finalRecyclePath))
	return nil
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

// syncFiles 执行文件同步逻辑
func syncFiles(media *string) {
	if err := loadConfig(); err != nil {
		addLog("error", fmt.Sprintf("初始加载配置文件失败：%v", err))
		return
	}
	intervalChange := make(chan int, 1)
	restartTicker := func(ticker *time.Ticker, interval int) *time.Ticker {
		if ticker != nil {
			ticker.Stop()
		}
		newTicker := time.NewTicker(time.Duration(interval) * time.Hour)
		addLog("info", fmt.Sprintf("新的同步间隔：%d 小时", interval))
		return newTicker
	}
	configMu.RLock()
	interval := config.Interval
	configMu.RUnlock()
	if interval <= 0 {
		interval = 12
		addLog("warning", "同步间隔无效，强制设置为 12 小时")
		configMu.Lock()
		config.Interval = interval
		configMu.Unlock()
		if err := saveConfig(); err != nil {
			addLog("error", fmt.Sprintf("保存默认间隔失败：%v", err))
		}
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Hour)
	defer ticker.Stop()
	mediaDir := filepath.Clean(*media)
	scanListGzPath := ".scan.list.gz"

	for {
		syncStateMu.Lock()
		running := syncState.Running
		syncStateMu.Unlock()

		if !running {
			select {
			case <-syncState.Trigger:
				syncStateMu.Lock()
				syncState.Running = true
				syncState.LastStart = time.Now()
				syncStateMu.Unlock()
				addLog("info", "手动启动同步，开始新一轮同步")
			case <-syncState.SyncDone:
				syncStateMu.Lock()
				syncState.Running = false
				syncStateMu.Unlock()
				addLog("info", "主同步任务暂停，等待触发")
				continue
			case newInterval := <-intervalChange:
				configMu.Lock()
				config.Interval = newInterval
				configMu.Unlock()
				ticker = restartTicker(ticker, newInterval)
				continue
			case <-ticker.C:
				syncStateMu.Lock()
				syncState.Running = true
				syncState.LastStart = time.Now()
				syncStateMu.Unlock()
				addLog("info", "定时器触发，进入下一次同步")
			case <-time.After(100 * time.Millisecond):
				continue
			}
		} else {
			syncStateMu.Lock()
			syncState.LastStart = time.Now()
			syncStateMu.Unlock()
		}

		startTime := time.Now()
		configMu.RLock()
		paths := config.ActivePaths
		if len(paths) == 0 {
			paths = config.SPathsAll
		}
		maxConcurrency := config.MaxConcurrency
		configMu.RUnlock()

		addLog("info", fmt.Sprintf("勾选同步路径：%v", paths))
		if !testMediaFolder(mediaDir, paths) {
			addLog("warning", fmt.Sprintf("%s 不包含所有目标文件夹，将创建缺失的目录", mediaDir))
		}

		// 清理 .tmp 文件
		err := filepath.Walk(mediaDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, ".tmp") {
				if err := os.Remove(path); err != nil {
					addLog("warning", fmt.Sprintf("清理临时文件 %s 失败：%v", path, err))
				} else {
					addLog("info", fmt.Sprintf("清理临时文件：%s", path))
				}
			}
			return nil
		})
		if err != nil {
			addLog("warning", fmt.Sprintf("清理临时文件失败：%v", err))
		}

		// 扫描本地文件（内存Map版本）
		localMap, err := scanLocalFilesToMap(mediaDir, paths)
		if err != nil {
			addLog("error", fmt.Sprintf("生成本地文件映射失败：%v", err))
			continue
		}

		// 选择服务器
		configMu.RLock()
		servers := pickBestServers(config.SPool)
		configMu.RUnlock()

		if len(servers) == 0 {
			addLog("error", "没有可用的服务器，等待 5 分钟后重试")
			select {
			case <-time.After(5 * time.Minute):
				continue
			case <-syncState.SyncDone:
				syncStateMu.Lock()
				syncState.Running = false
				syncStateMu.Unlock()
				addLog("info", "主同步任务暂停，等待触发")
				continue
			}
		}

		url := servers[0].URL
		addLog("info", fmt.Sprintf("使用服务器：%s", url))

		// 检查并下载 .scan.list.gz
		isSame, serverTime, err := checkAndUpdateScanList(url, scanListGzPath)
		if err != nil {
			addLog("error", fmt.Sprintf("检查并更新数据包失败：%v", err))
			continue
		}

		if isSame {
			configMu.RLock()
			nextRun := time.Now().Add(time.Duration(config.Interval) * time.Hour)
			configMu.RUnlock()
			addLog("info", fmt.Sprintf("服务器数据一致，等待下次检测，下次时间：%s", formatTime(nextRun)))

			syncStateMu.Lock()
			running := syncState.Running
			syncStateMu.Unlock()

			if running {
				select {
				case <-syncState.Trigger:
					addLog("info", "手动触发同步，跳过等待")
				case <-ticker.C:
					addLog("info", "定时器触发，进入下一次同步")
				case <-syncState.SyncDone:
					syncStateMu.Lock()
					syncState.Running = false
					syncStateMu.Unlock()
					addLog("info", "主同步任务暂停，等待触发")
					continue
				case <-time.After(time.Duration(interval) * time.Hour):
					addLog("warning", "同步超时，强制进入下一次循环")
				}
			}
			continue
		}

		// 生成服务器文件映射
		serverMap, err := generateServerMap(scanListGzPath, paths)
		if err != nil {
			addLog("error", fmt.Sprintf("生成服务器文件映射失败：%v", err))
			continue
		}

		// 删除 .scan.list.gz
		if err := os.Remove(scanListGzPath); err != nil && !os.IsNotExist(err) {
			addLog("warning", fmt.Sprintf("删除数据包文件失败：%v", err))
		}

		// 对比差异
		toUpdate, toDelete, err := compareAndPrepareSync(localMap.Files, serverMap, paths)
		if err != nil {
			addLog("error", fmt.Sprintf("比较文件映射失败：%v", err))
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-syncState.SyncDone:
				addLog("info", "主同步任务被停止")
				cancel()
			case <-ctx.Done():
			}
		}()

		// 执行核心同步
		successFiles, failedFiles, err := syncFilesCore(ctx, mediaDir, servers, toUpdate, toDelete, maxConcurrency, true)
		cancel()

		// 更新本地路径计数
		updateLocalPathCounts(localMap, paths)

		// 处理同步结果
		syncStateMu.Lock()
		running = syncState.Running
		syncStateMu.Unlock()

		if err == context.Canceled {
			addLog("info", fmt.Sprintf("主同步被手动终止，耗时 %s，未更新 scanListTime", formatDuration(time.Since(startTime))))
			if running {
				addLog("info", "同步被终止，但运行状态仍为 true，立即开始新一轮同步")
				continue
			}
			syncStateMu.Lock()
			syncState.Running = false
			syncStateMu.Unlock()
			addLog("info", "主同步任务暂停，等待触发")
			continue
		}

		// 更新 scanListTime
		configMu.Lock()
		config.ScanListTime = serverTime
		if err := saveConfig(); err != nil {
			addLog("error", fmt.Sprintf("更新配置文件时间失败：%v", err))
		}
		configMu.Unlock()

		addLog("info", fmt.Sprintf("本地数据日期 为 %s", formatTime(serverTime)))

		if err != nil {
			addLog("error", fmt.Sprintf("核心同步失败：%v", err))
			select {
			case <-time.After(5 * time.Minute):
				continue
			case <-syncState.SyncDone:
				syncStateMu.Lock()
				syncState.Running = false
				syncStateMu.Unlock()
				addLog("info", "主同步任务暂停，等待触发")
				continue
			}
		}

		if running {
			if len(failedFiles) > 0 {
				addLog("warning", fmt.Sprintf("主同步完成，成功 %d 个文件，失败 %d 个文件，耗时 %s",
					len(successFiles), len(failedFiles), formatDuration(time.Since(startTime))))
			} else {
				addLog("success", fmt.Sprintf("主同步完成，成功 %d 个文件，耗时 %s",
					len(successFiles), formatDuration(time.Since(startTime))))
			}

			configMu.RLock()
			nextRun := time.Now().Add(time.Duration(config.Interval) * time.Hour)
			configMu.RUnlock()

			addLog("info", fmt.Sprintf("同步完成，进入等待状态，下次检测时间：%s", formatTime(nextRun)))

			syncStateMu.Lock()
			syncState.LastStart = time.Now()
			syncStateMu.Unlock()
		}

		// 等待下一轮同步
		select {
		case <-syncState.Trigger:
			addLog("info", "手动触发同步，立即开始新一轮同步")
			continue
		case <-ticker.C:
			addLog("info", "定时器触发，进入下一轮同步")
			continue
		case <-syncState.SyncDone:
			syncStateMu.Lock()
			syncState.Running = false
			syncStateMu.Unlock()
			addLog("info", "主同步任务暂停，等待触发")
			continue
		case <-time.After(time.Duration(interval) * time.Hour):
			addLog("warning", "同步超时，强制进入下一次循环")
			continue
		}
	}
}

// updateLocalPathCounts 使用内存Map更新本地路径计数
func updateLocalPathCounts(localMap *LocalFileInfo, paths []string) {
	configMu.Lock()
	defer configMu.Unlock()

	if config.LocalPathCounts == nil {
		config.LocalPathCounts = make(map[string]int)
	}

	// 直接使用传入的 LocalFileInfo 结构体中的计数
	for path, count := range localMap.Counts {
		config.LocalPathCounts[path] = count
	}

	// 清理不再存在的路径
	for path := range config.LocalPathCounts {
		found := false
		for _, p := range paths {
			if p == path {
				found = true
				break
			}
		}
		if !found {
			delete(config.LocalPathCounts, path)
		}
	}

	// 保存配置
	if err := saveConfig(); err != nil {
		addLog("error", fmt.Sprintf("保存路径计数失败：%v", err))
	}
}

// syncFilesCore 执行文件同步核心逻辑
func syncFilesCore(ctx context.Context, mediaDir string, servers []ServerInfo, toUpdate []FileInfo, toDelete []string, maxConcurrency int, deleteFiles bool) ([]FileInfo, []string, error) {
	startTime := time.Now()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrency)
	successFiles := make([]FileInfo, 0, len(toUpdate))
	failedFiles := make([]string, 0, len(toDelete)+len(toUpdate))
	var successMu, failedMu sync.Mutex

	// 第一步：处理删除
	if deleteFiles && len(toDelete) > 0 {
		addLog("info", "开始处理本地多余文件的删除")
		for _, path := range toDelete {
			select {
			case <-ctx.Done():
				addLog("info", "核心同步文件删除被取消")
				return successFiles, failedFiles, ctx.Err()
			default:
				wg.Add(1)
				go func(p string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					if err := deleteLocalFile(mediaDir, p); err != nil {
						failedMu.Lock()
						failedFiles = append(failedFiles, p)
						failedMu.Unlock()
						addLog("error", fmt.Sprintf("删除 %s 失败：%v", p, err))
					}
				}(path)
			}
		}
		wg.Wait() // 等待删除完成
		addLog("info", fmt.Sprintf("删除完成，成功 %d 个，失败 %d 个", len(toDelete)-len(failedFiles), len(failedFiles)))
	}

	// 第二步：处理下载
	if len(toUpdate) > 0 {
		addLog("info", "开始处理文件下载和更新")
		for _, file := range toUpdate {
			select {
			case <-ctx.Done():
				addLog("info", "核心同步文件下载被取消")
				return successFiles, failedFiles, ctx.Err()
			default:
				wg.Add(1)
				go func(f FileInfo) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					cleanedPath := filepath.Join(filepath.Dir(f.Path), cleanFileName(filepath.Base(f.Path)))
					if err := downloadFile(ctx, f, servers, mediaDir, cleanedPath); err != nil {
						failedMu.Lock()
						failedFiles = append(failedFiles, f.Path)
						failedMu.Unlock()
						addLog("error", fmt.Sprintf("下载 %s 失败：%v", f.Path, err))
					} else {
						successMu.Lock()
						successFiles = append(successFiles, f)
						successMu.Unlock()
					}
				}(file)
			}
		}
		wg.Wait() // 等待下载完成
	}

	// 如果任务被取消，跳过后续处理
	if ctx.Err() != nil {
		addLog("info", fmt.Sprintf("核心同步被终止，耗时 %s", formatDuration(time.Since(startTime))))
		return successFiles, failedFiles, ctx.Err()
	}

	addLog("success", fmt.Sprintf("核心同步完成，更新 %d 个文件，删除 %d 个文件，耗时 %s", len(successFiles), len(toDelete)-len(failedFiles), formatDuration(time.Since(startTime))))
	return successFiles, failedFiles, nil
}

// getRootDir 获取文件路径的根目录
func getRootDir(filePath string) string {
	parts := strings.Split(strings.TrimPrefix(filePath, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0] + "/"
}

// checkAndUpdateScanList 检查并下载 .scan.list.gz 文件
func checkAndUpdateScanList(serverURL, localPath string) (bool, time.Time, error) {
	//addLog("info", fmt.Sprintf("检查服务器 %s 数据包时间", serverURL))
	resp, err := httpClient.Get(serverURL + "/.scan.list.gz")
	if err != nil {
		return false, time.Time{}, fmt.Errorf("请求服务器数据包失败：%v", err)
	}
	defer resp.Body.Close()

	serverTimeStr := resp.Header.Get("Last-Modified")
	serverTime, err := time.Parse(time.RFC1123, serverTimeStr)
	if err != nil {
		addLog("warning", fmt.Sprintf("解析服务器数据包生成时间失败：%v，使用当前时间", err))
		serverTime = time.Now()
	}

	configMu.RLock()
	scanListTime := config.ScanListTime
	configMu.RUnlock()
	if scanListTime.IsZero() {
		addLog("info", "本地数据时间未设置")
	} else {
		addLog("info", fmt.Sprintf("本地数据时间：%s", formatTime(scanListTime)))
	}

	localStat, err := os.Stat(localPath)
	localTime := time.Time{}
	if err == nil {
		localTime = localStat.ModTime()
		addLog("info", fmt.Sprintf("本地数据包生成时间：%s", formatTime(localTime)))
	}

	compareTime := scanListTime
	if compareTime.IsZero() {
		compareTime = localTime
	}

	if !compareTime.IsZero() && serverTime.Sub(compareTime) <= 30*time.Minute {
		addLog("info", fmt.Sprintf("服务器数据包与本地时间一致（时间差：%s），无需更新", serverTime.Sub(compareTime)))
		return true, serverTime, nil
	}
	addLog("info", fmt.Sprintf("需更新数据包（时间差：%s）", serverTime.Sub(compareTime)))

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, serverTime, fmt.Errorf("读取服务器数据包失败：%v", err)
	}

	localFile, err := os.Create(localPath)
	if err != nil {
		return false, serverTime, fmt.Errorf("创建本地数据包失败：%v", err)
	}
	defer localFile.Close()
	if _, err := localFile.Write(body); err != nil {
		return false, serverTime, fmt.Errorf("写入本地数据包失败：%v", err)
	}

	if err := os.Chtimes(localPath, serverTime, serverTime); err != nil {
		addLog("error", fmt.Sprintf("设置 %s 的时间失败：%v", localPath, err))
	}

	addLog("info", "数据包文件已更新")
	return false, serverTime, nil
}

// generateServerMap 解析.gz文件生成内存Map
func generateServerMap(gzPath string, activePaths []string) (FileInfoMap, error) {
	startTime := time.Now()
	fileMap := make(FileInfoMap)

	gzFile, err := os.Open(gzPath)
	if err != nil {
		return nil, err
	}
	defer gzFile.Close()

	gz, err := gzip.NewReader(gzFile)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	scanner := bufio.NewScanner(gz)
	pattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2} /(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()
		match := pattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		filePath := match[1]
		timestampStr := strings.Fields(line)[0] + " " + strings.Fields(line)[1]
		t, _ := time.Parse("2006-01-02 15:04", timestampStr)

		// 路径过滤
		for _, path := range activePaths {
			if strings.HasPrefix(filePath, path) {
				fileMap[filePath] = t.Unix()
				break
			}
		}
	}
	addLog("success", fmt.Sprintf("服务器数据生成完成，共 %d 条记录，耗时 %s",
		len(fileMap), formatDuration(time.Since(startTime))))
	return fileMap, nil
}

// formatDuration 格式化时间间隔，保留小数点后两位
func formatDuration(d time.Duration) string {
	seconds := float64(d) / float64(time.Second)
	return fmt.Sprintf("%.2f秒", seconds)
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
	if newConfig.SPathsAll == nil && newConfig.SPool == nil && newConfig.ActivePaths == nil && newConfig.Interval == nil && newConfig.DNSType == nil && newConfig.DNSServer == nil && newConfig.DNSEnabled == nil && newConfig.LogSize == nil && newConfig.BandwidthLimitEnabled == nil && newConfig.BandwidthLimitMBps == nil && newConfig.MaxConcurrency == nil {
		http.Error(w, "至少需要提供一个配置字段", http.StatusBadRequest)
		return
	}

	dnsChanged := false
	bandwidthChanged := false
	configMu.Lock()
	if newConfig.SPathsAll != nil {
		config.SPathsAll = *newConfig.SPathsAll
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
		// 通知 syncFiles 重启 ticker
		select {
		case intervalChange <- *newConfig.Interval:
		default:
			addLog("warning", "intervalChange 通道已满，ticker 可能未更新")
		}
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

	configMu.RLock()
	pathCounts := make(map[string]int)
	for _, path := range config.SPathsAll {
		count, exists := config.LocalPathCounts[path]
		if !exists {
			pathCounts[path] = -1 // 表示未知
		} else {
			pathCounts[path] = count
		}
	}
	message := ""
	if len(config.LocalPathCounts) == 0 {
		message = "本地文件计数未生成，请触发刷新"
	}
	configMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"counts":  pathCounts,
		"message": message,
	})
}

// handleServerPathsCount 返回服务器路径的文件数量
func handleServerPathsCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	configMu.RLock()
	defer configMu.RUnlock()

	pathCounts := make(map[string]int)
	for _, path := range config.SPathsAll {
		count, exists := config.ServerPathCounts[path]
		if !exists {
			pathCounts[path] = -1 // 表示未知
		} else {
			pathCounts[path] = count
		}
	}
	json.NewEncoder(w).Encode(pathCounts)
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
		nextRun = formatTime(syncState.LastStart.Add(time.Duration(config.Interval) * time.Hour))
	}
	message := "同步 " + map[bool]string{true: "运行中", false: "已停止"}[syncState.Running]
	json.NewEncoder(w).Encode(struct {
		IsRunning bool   `json:"isRunning"`
		Message   string `json:"message"`
		NextRun   string `json:"nextRun"`
		Interval  int    `json:"interval"`
	}{
		IsRunning: syncState.Running,
		Message:   message,
		NextRun:   nextRun,
		Interval:  config.Interval,
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
	// 非阻塞发送触发信号
	select {
	case syncState.Trigger <- struct{}{}:
		addLog("info", "触发信号已发送")
	default:
		addLog("warning", "触发信号队列已满，同步可能已在处理")
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleSyncStop 停止同步
func handleSyncStop(w http.ResponseWriter, r *http.Request) {
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	if syncState.Running {
		syncState.Running = false
		select {
		case syncState.SyncDone <- struct{}{}:
			addLog("info", "手动停止主同步") // 修改：在锁内调用
		default:
			addLog("warning", "停止信号队列已满") // 新增
		}
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

// filterValidServers 过滤无效的服务器 URL
func filterValidServers(servers []string) []string {
	var validServers []string
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
			server = "https://" + server
		}
		if _, err := url.ParseRequestURI(server); err == nil {
			validServers = append(validServers, server)
		}
	}
	return validServers
}

// filterValidPaths 过滤无效的目录路径并规范化
func filterValidPaths(paths []string) []string {
	var validPaths []string
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		// 清理非法字符并确保路径以 / 结尾
		path = cleanFileName(path)
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		validPaths = append(validPaths, path)
	}
	// 去重
	uniquePaths := make([]string, 0, len(validPaths))
	seen := make(map[string]bool)
	for _, path := range validPaths {
		if !seen[path] {
			seen[path] = true
			uniquePaths = append(uniquePaths, path)
		}
	}
	return uniquePaths
}

// intersectPaths 返回两个路径切片的交集
func intersectPaths(active, all []string) []string {
	allSet := make(map[string]bool)
	for _, path := range all {
		allSet[path] = true
	}
	var result []string
	for _, path := range active {
		if allSet[path] {
			result = append(result, path)
		}
	}
	return result
}

// validateMediaDir 验证 media 目录是否有效
func validateMediaDir(mediaDir string) error {
	// 检查目录是否存在
	stat, err := os.Stat(mediaDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("媒体目录 %s 不存在", mediaDir)
		}
		return fmt.Errorf("检查媒体目录 %s 失败：%v", mediaDir, err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("媒体目录 %s 不是一个目录", mediaDir)
	}

	// 检查是否存在“每日更新”文件夹
	dailyUpdatePath := filepath.Join(mediaDir, "每日更新")
	if _, err := os.Stat(dailyUpdatePath); os.IsNotExist(err) {
		return fmt.Errorf("媒体目录 %s 下缺少 '每日更新' 文件夹", mediaDir)
	} else if err != nil {
		return fmt.Errorf("检查 '每日更新' 文件夹失败：%v", err)
	}

	return nil
}

// checkMediaPermissions 检查媒体目录的读、写、执行权限
func checkMediaPermissions(mediaDir string) error {
	// 检查读权限：尝试打开目录并读取内容
	dir, err := os.Open(mediaDir)
	if err != nil {
		return fmt.Errorf("无读权限（无法打开目录）：%v", err)
	}
	_, err = dir.Readdirnames(1) // 尝试读取至少一个条目
	dir.Close()
	if err != nil && err != io.EOF {
		return fmt.Errorf("无读权限（无法读取目录内容）：%v", err)
	}

	// 检查执行权限：检查文件模式并尝试访问子目录
	stat, err := os.Stat(mediaDir)
	if err != nil {
		return fmt.Errorf("无法获取目录权限信息：%v", err)
	}
	mode := stat.Mode()
	if mode&0o100 == 0 { // 检查用户执行权限
		return fmt.Errorf("无执行权限（目录不可遍历）")
	}
	// 验证子目录访问（每日更新由 validateMediaDir 保证存在）
	dailyUpdatePath := filepath.Join(mediaDir, "每日更新")
	if _, err := os.Stat(dailyUpdatePath); err != nil {
		return fmt.Errorf("无执行权限（无法访问子目录）：%v", err)
	}

	// 检查写权限：尝试创建并删除临时文件
	tempFile := filepath.Join(mediaDir, ".perm_test")
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("无写权限（无法创建文件）：%v", err)
	}
	file.Close()
	if err := os.Remove(tempFile); err != nil {
		return fmt.Errorf("无写权限（无法删除文件）：%v", err)
	}

	return nil
}

// handleRecycleBinCount 返回回收站文件数量
func handleRecycleBinCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mediaDir := flag.Lookup("media").Value.String()
	recycleDir := filepath.Join(mediaDir, "recycle_bin")
	var fileCount int
	err := filepath.Walk(recycleDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, "统计回收站文件失败", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]int{"fileCount": fileCount})
}

// handleRecycleBinClear 清空回收站
func handleRecycleBinClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	mediaDir := flag.Lookup("media").Value.String()
	recycleDir := filepath.Join(mediaDir, "recycle_bin")

	// 统计文件数量
	var fileCount int
	err := filepath.Walk(recycleDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, "统计回收站文件失败", http.StatusInternalServerError)
		return
	}

	// 直接删除整个 recycle_bin 文件夹
	if err := os.RemoveAll(recycleDir); err != nil {
		http.Error(w, "清空回收站失败", http.StatusInternalServerError)
		return
	}

	// 重新创建空的 recycle_bin 文件夹
	if err := os.MkdirAll(recycleDir, 0777); err != nil {
		http.Error(w, "重建回收站目录失败", http.StatusInternalServerError)
		return
	}

	addLog("success", fmt.Sprintf("回收站已清空，删除 %d 个文件", fileCount))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("已清空 %d 个文件", fileCount),
	})
}

// handleRecycleBinList 返回回收站文件树列表
func handleRecycleBinList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	mediaDir := flag.Lookup("media").Value.String()
	recycleDir := filepath.Join(mediaDir, "recycle_bin")

	var filePaths []string
	err := filepath.Walk(recycleDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relativePath, err := filepath.Rel(mediaDir, path)
			if err != nil {
				return err
			}
			relativePath = filepath.ToSlash(relativePath)
			filePaths = append(filePaths, relativePath)
		}
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		addLog("error", fmt.Sprintf("遍历回收站目录失败：%v", err))
		http.Error(w, "获取回收站文件列表失败", http.StatusInternalServerError)
		return
	}

	// 如果回收站为空，返回提示
	if len(filePaths) == 0 {
		w.Write([]byte("回收站为空"))
		return
	}

	// 按路径排序，确保输出有序
	sort.Strings(filePaths)
	// 拼接 TXT 内容，每行一个路径
	output := strings.Join(filePaths, "\n")
	w.Write([]byte(output))
}

// handleResetScanListTime 将 scanListTime 重置为固定时间以触发同步
func handleResetScanListTime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	configMu.Lock()
	oldTime := config.ScanListTime
	config.ScanListTime = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := saveConfig(); err != nil {
		configMu.Unlock()
		http.Error(w, "保存配置文件失败", http.StatusInternalServerError)
		return
	}
	configMu.Unlock()

	syncStateMu.Lock()
	select {
	case syncState.Trigger <- struct{}{}:
		addLog("info", "重置数据包时间后触发主同步")
	default:
		addLog("warning", "触发信号队列已满，主同步可能已在处理")
	}
	syncStateMu.Unlock()

	addLog("info", fmt.Sprintf("数据包日期 从 %s 重置为 %s", formatTime(oldTime), formatTime(config.ScanListTime)))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "数据包时间已重置，已触发同步",
	})
}
func main() {
	var err error
	shanghaiLoc, err = time.LoadLocation("Asia/Shanghai")
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载时区失败：%v\n", err)
		os.Exit(1)
	}
	media := flag.String("media", "", "存储下载媒体文件的路径（必须）")
	port := flag.Int("port", 8080, "HTTP 服务器端口（默认 8080）")
	flag.Parse()
	// 初始化日志缓冲区（使用默认大小，稍后根据配置调整）
	logsMu.Lock()
	logs = ring.New(50000) // 初始默认大小 50000
	logsMu.Unlock()
	// 加载配置文件
	if err := loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "加载配置文件失败：%v\n", err)
		os.Exit(1)
	}
	// 下载服务器列表并更新 sPool
	fmt.Fprintf(os.Stdout, "尝试更新爬虫服务器列表,请稍等...\n")
	resp, err := http.Get("https://docker.xiaoya.pro/crawler_sites.list")
	if err != nil {
		fmt.Fprintf(os.Stderr, "下载服务器列表失败：%v，使用默认列表.\n", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "读取服务器列表失败：%v，使用默认列表.\n", err)
			} else {
				servers := strings.Split(strings.TrimSpace(string(body)), "\n")
				servers = filterValidServers(servers)
				if len(servers) > 0 {
					configMu.Lock()
					config.SPool = servers
					configMu.Unlock()
					if err := saveConfig(); err != nil {
						fmt.Fprintf(os.Stderr, "保存服务器列表到配置文件失败：%v\n", err)
					} else {
						fmt.Fprintf(os.Stdout, "服务器列表更新成功，共 %d 个服务器\n", len(servers))
					}
				} else {
					fmt.Fprintf(os.Stderr, "使用默认服务器列表\n")
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "下载服务器列表失败，状态码：%d，使用默认列表.\n", resp.StatusCode)
		}
	}

	// 下载目录列表并更新 sPathsAll
	fmt.Fprintf(os.Stdout, "尝试更新媒体列表,请稍等...\n")
	resp, err = http.Get("https://docker.xiaoya.pro/crawler_dir.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "下载目录列表失败：%v，使用默认列表.\n", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "读取目录列表失败：%v，使用默认列表.\n", err)
			} else {
				paths := strings.Split(strings.TrimSpace(string(body)), "\n")
				paths = filterValidPaths(paths)
				if len(paths) > 0 {
					configMu.Lock()
					config.SPathsAll = paths
					config.ActivePaths = intersectPaths(config.ActivePaths, paths)
					configMu.Unlock()
					if err := saveConfig(); err != nil {
						fmt.Fprintf(os.Stderr, "保存目录列表到配置文件失败：%v\n", err)
					} else {
						fmt.Fprintf(os.Stdout, "目录列表更新成功，共 %d 个目录\n", len(paths))
					}
				} else {
					fmt.Fprintf(os.Stderr, "使用默认目录列表\n")
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "下载目录列表失败，状态码：%d，使用默认列表.\n", resp.StatusCode)
		}
	}

	logsMu.Lock()
	logs = ring.New(config.LogSize)
	logsMu.Unlock()

	if *port < 1 || *port > 65535 {
		fmt.Fprintf(os.Stderr, "端口 %d 无效，必须在 1-65535 范围内\n", *port)
		os.Exit(1)
	}
	if err := validateMediaDir(*media); err != nil {
		fmt.Fprintf(os.Stderr, "无效的媒体目录：%v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "媒体目录 %s 有效,", *media)
	if err := checkMediaPermissions(*media); err != nil {
		fmt.Fprintf(os.Stderr, " %s 权限不足：%v\n", *media, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "权限检查通过，具备读、写、执行权限\n")
	initHttpClient()

	addLog("info", "程序初始化完成，开始后台同步")
	go syncFiles(media)

	subFS, _ := fs.Sub(staticFiles, "static")
	fs := http.FileServer(http.FS(subFS))
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
	http.HandleFunc("/api/refresh-local", handleRefreshLocal)
	http.HandleFunc("/api/recycle-bin/count", handleRecycleBinCount)
	http.HandleFunc("/api/recycle-bin/clear", handleRecycleBinClear)
	http.HandleFunc("/api/recycle-bin/list", handleRecycleBinList)
	http.HandleFunc("/api/reset-scanlist-time", handleResetScanListTime)
	http.Handle("/", fs)

	addr := fmt.Sprintf(":%d", *port)
	fmt.Fprintf(os.Stdout, "页面已启动，请访问端口 %d\n", *port)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "服务器启动失败：%v\n", err)
		addLog("error", fmt.Sprintf("服务器启动失败（端口 %d）：%v", *port, err))
		os.Exit(1)
	}
}
