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

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

//go:embed static/*
var staticFiles embed.FS

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
	Running      bool
	Trigger      chan struct{}
	LastStart    time.Time
	SyncingPath  string
	SyncDone     chan struct{} // 通知主同步退出
	StopPathSync chan struct{} // 通知路径同步停止
	FromPathSync bool          // 标记是否从路径同步触发
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

// DBFileInfo 定义数据库文件信息结构
type DBFileInfo struct {
	Path      string `db:"path"`
	Timestamp int64  `db:"timestamp"`
}

// 全局变量
var (
	localDB    *sqlx.DB
	tempDB     *sqlx.DB
	dbMu       sync.Mutex
	config     Config
	configMu   sync.RWMutex
	httpClient *http.Client
	logs       *ring.Ring
	logsMu     sync.Mutex
	syncState  = SyncState{
		Running:      true,
		Trigger:      make(chan struct{}, 1),
		SyncDone:     make(chan struct{}),
		StopPathSync: make(chan struct{}),
		FromPathSync: false, // 初始化 FromPathSync
	}
	syncStateMu sync.Mutex
	shanghaiLoc *time.Location // 东八区时区
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
	configFile, err := os.Open("config.json")
	if err != nil {
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
	if newConfig.PathUpdateNotices == nil {
		newConfig.PathUpdateNotices = make(map[string]bool)
	}
	if newConfig.ServerPathCounts == nil {
		newConfig.ServerPathCounts = make(map[string]int)
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

// initLocalDB 初始化本地数据库
func initLocalDB(dbPath string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败：%v", err)
	}

	// 启用 WAL 模式以支持并发读写
	_, err = db.Exec(`PRAGMA journal_mode=WAL`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("启用 WAL 模式失败：%v", err)
	}

	// 设置同步模式为 NORMAL，平衡性能和耐久性
	_, err = db.Exec(`PRAGMA synchronous=NORMAL`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("设置 synchronous 失败：%v", err)
	}

	// 创建 files 表，path 为主键（自动创建唯一索引）
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS files (
        path TEXT PRIMARY KEY,
        timestamp INTEGER
    )`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("创建表失败：%v", err)
	}

	return db, nil
}

// handleRefreshLocal 刷新本地文件数据库
func handleRefreshLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	mediaDir := flag.Lookup("media").Value.String()
	if mediaDir == "" {
		addLog("error", "未提供 --media 参数")
		http.Error(w, "未配置媒体目录", http.StatusInternalServerError)
		return
	}

	localDBPath := "local_files.db"

	// 重新扫描本地文件并插入数据库
	if err := scanLocalFiles(mediaDir, localDBPath); err != nil {
		addLog("error", fmt.Sprintf("刷新本地数据库失败：%v", err))
		http.Error(w, "刷新本地数据库失败", http.StatusInternalServerError)
		return
	}

	addLog("success", "本地文件数据库刷新完成")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// scanLocalFiles 扫描本地文件并生成数据库
func scanLocalFiles(mediaDir, dbPath string) error {
	// 检查数据库是否存在
	_, statErr := os.Stat(dbPath)
	isNewDB := os.IsNotExist(statErr)
	if statErr != nil && !isNewDB {
		return fmt.Errorf("检查数据库 %s 失败：%v", dbPath, statErr)
	}

	// 根据场景记录日志
	logMsg := "首次运行，初始化本地数据库"
	if !isNewDB {
		logMsg = "本地数据库已存在，重新扫描文件"
	}

	// 初始化或使用全局 localDB
	dbMu.Lock()
	if localDB == nil {
		var err error
		localDB, err = initLocalDB(dbPath)
		if err != nil {
			dbMu.Unlock()
			return err
		}
	}
	dbMu.Unlock()

	// 获取要扫描的目录
	configMu.RLock()
	paths := config.SPathsAll
	configMu.RUnlock()

	var totalFiles int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 统计所有目录的总文件数
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			dirPath := filepath.Join(mediaDir, p)
			err := filepath.Walk(dirPath, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					mu.Lock()
					totalFiles++
					mu.Unlock()
				}
				return nil
			})
			if err != nil && !os.IsNotExist(err) {
				addLog("warning", fmt.Sprintf("扫描目录 %s 失败：%v", p, err))
			}
		}(path)
	}
	wg.Wait()

	if totalFiles == 0 {
		addLog("info", "指定目录中没有文件，数据库生成完成")
		return nil
	}

	startTime := time.Now()
	processedFiles := 0
	var processedMu sync.Mutex
	lastProgress := -10

	tx, err := localDB.Beginx()
	if err != nil {
		return fmt.Errorf("启动事务失败：%v", err)
	}

	// 清空现有记录（如果是刷新场景）
	if !isNewDB {
		_, err = tx.Exec(`DELETE FROM files`)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("清空数据库表失败：%v", err)
		}
	}

	// 扫描每个目录并插入数据库
	for _, path := range paths {
		dirPath := filepath.Join(mediaDir, path)
		err := filepath.Walk(dirPath, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			relativePath, err := filepath.Rel(mediaDir, filePath)
			if err != nil {
				return err
			}
			relativePath = filepath.ToSlash(relativePath)
			timestamp := info.ModTime().Unix()

			_, err = tx.Exec(`INSERT OR REPLACE INTO files (path, timestamp) VALUES (?, ?)`, relativePath, timestamp)
			if err != nil {
				return fmt.Errorf("插入文件记录失败：%v", err)
			}

			processedMu.Lock()
			processedFiles++
			progress := int(float64(processedFiles) / float64(totalFiles) * 100)
			if progress >= lastProgress+10 {
				addLog("info", fmt.Sprintf("本地数据库生成进度：%d%% (%d/%d 文件)", progress, processedFiles, totalFiles))
				lastProgress = progress - (progress % 10)
			}
			processedMu.Unlock()
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			tx.Rollback()
			return fmt.Errorf("扫描目录 %s 失败：%v", path, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败：%v", err)
	}

	duration := time.Since(startTime)
	logMsg = fmt.Sprintf("本地数据库 %s 生成完成，共 %d 个文件，耗时 %s", dbPath, processedFiles, formatDuration(duration))
	addLog("success", logMsg)
	return nil
}

// compareAndPrepareSync 比较数据库并准备同步文件
func compareAndPrepareSync(localDBPath, tempDBPath string, paths []string) ([]FileInfo, []string, error) {
	addLog("info", "开始比较本地和临时数据库")
	dbMu.Lock()
	if localDB == nil {
		var err error
		localDB, err = initLocalDB(localDBPath)
		if err != nil {
			dbMu.Unlock()
			return nil, nil, fmt.Errorf("初始化本地数据库失败：%v", err)
		}
	}
	if tempDB == nil {
		var err error
		tempDB, err = initLocalDB(tempDBPath)
		if err != nil {
			dbMu.Unlock()
			return nil, nil, fmt.Errorf("初始化临时数据库失败：%v", err)
		}
	}
	dbMu.Unlock()

	var localFiles []DBFileInfo
	err := localDB.Select(&localFiles, `SELECT path, timestamp FROM files`)
	if err != nil {
		return nil, nil, fmt.Errorf("查询本地数据库失败：%v", err)
	}

	var tempFiles []DBFileInfo
	err = tempDB.Select(&tempFiles, `SELECT path, timestamp FROM files`)
	if err != nil {
		return nil, nil, fmt.Errorf("查询临时数据库失败：%v", err)
	}

	localMap := make(map[string]int64)
	for _, f := range localFiles {
		localMap[f.Path] = f.Timestamp
	}

	tempMap := make(map[string]int64)
	for _, f := range tempFiles {
		tempMap[f.Path] = f.Timestamp
	}

	var toUpdate []FileInfo
	var toDelete []string

	for path, tempTimestamp := range tempMap {
		shouldSync := false
		for _, p := range paths {
			if strings.HasPrefix(path, p) {
				shouldSync = true
				break
			}
		}
		if !shouldSync {
			continue
		}
		localTimestamp, exists := localMap[path]
		if !exists || time.Duration(tempTimestamp-localTimestamp)*time.Second > 10*time.Minute {
			toUpdate = append(toUpdate, FileInfo{Path: path, Timestamp: tempTimestamp})
		}
	}

	for path := range localMap {
		shouldDelete := false
		for _, p := range paths {
			if strings.HasPrefix(path, p) {
				shouldDelete = true
				break
			}
		}
		if !shouldDelete {
			continue
		}
		if _, exists := tempMap[path]; !exists {
			toDelete = append(toDelete, path)
		}
	}

	// 不再删除 temp_files.db 中本地已存在的记录，保持全量数据
	// 更新 PathUpdateNotices
	configMu.Lock()
	if config.PathUpdateNotices == nil {
		config.PathUpdateNotices = make(map[string]bool)
	}
	for _, file := range toUpdate {
		rootDir := strings.SplitN(file.Path, "/", 2)[0]
		for _, p := range config.SPathsAll {
			if p == rootDir && !contains(paths, p) {
				config.PathUpdateNotices[p] = true
			}
		}
	}
	saveConfig()
	configMu.Unlock()

	addLog("info", fmt.Sprintf("数据库比较完成，需更新 %d 个文件，需删除 %d 个文件，temp_files.db 保持全量数据", len(toUpdate), len(toDelete)))
	return toUpdate, toDelete, nil
}

// 修改后的 downloadFile 函数，支持上下文取消
func downloadFile(ctx context.Context, file FileInfo, servers []ServerInfo, media, cleanedPath string) error {
	localPath := filepath.Join(media, cleanedPath)
	if err := os.MkdirAll(filepath.Dir(localPath), 0777); err != nil {
		return fmt.Errorf("创建目录失败：%v", err)
	}
	for i, server := range servers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			encodedUrlPath := url.PathEscape(file.Path)
			url := server.URL + "/" + encodedUrlPath
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				addLog("warning", fmt.Sprintf("创建请求 %s 失败：%v", file.Path, err))
				continue
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				addLog("warning", fmt.Sprintf("从服务器 %s 下载 %s 失败：%v", server.URL, file.Path, err))
				if i < len(servers)-1 {
					addLog("info", fmt.Sprintf("尝试备用服务器 %s", servers[i+1].URL))
					continue
				}
				return fmt.Errorf("所有服务器下载 %s 失败，最后错误：%v", file.Path, err) // 修改：添加最后错误
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
	}
	return fmt.Errorf("所有服务器下载 %s 失败", file.Path)
}

// deleteLocalFile 删除本地文件，移动到回收站
func deleteLocalFile(mediaDir, path string) error {
	localPath := filepath.Join(mediaDir, path)
	recycleDir := filepath.Join(mediaDir, "recycle_bin")
	recyclePath := filepath.Join(recycleDir, path)

	// 验证文件存在性
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		addLog("warning", fmt.Sprintf("文件 %s 不存在，跳过移动到回收站（原因：在 temp_files.db 中不存在）", path))
		return fmt.Errorf("文件 %s 不存在", path)
	} else if err != nil {
		addLog("error", fmt.Sprintf("检查文件 %s 失败：%v（原因：在 temp_files.db 中不存在）", path, err))
		return fmt.Errorf("检查文件 %s 失败：%v", path, err)
	}

	// 确保回收站目录存在
	if err := os.MkdirAll(filepath.Dir(recyclePath), 0777); err != nil {
		addLog("error", fmt.Sprintf("创建回收站目录 %s 失败：%v（原因：在 temp_files.db 中不存在）", filepath.Dir(recyclePath), err))
		return fmt.Errorf("创建回收站目录 %s 失败：%v", filepath.Dir(recyclePath), err)
	}

	// 处理同名文件冲突
	finalRecyclePath := recyclePath
	if _, err := os.Stat(recyclePath); err == nil {
		ext := filepath.Ext(path)
		base := strings.TrimSuffix(filepath.Base(path), ext)
		timestamp := time.Now().Format("20060102_150405")
		newBase := fmt.Sprintf("%s_%s%s", base, timestamp, ext)
		finalRecyclePath = filepath.Join(filepath.Dir(recyclePath), newBase)
	}

	// 移动文件到回收站
	if err := os.Rename(localPath, finalRecyclePath); err != nil {
		addLog("error", fmt.Sprintf("移动文件 %s 到回收站 %s 失败：%v（原因：在 temp_files.db 中不存在）", path, finalRecyclePath, err))
		return fmt.Errorf("移动文件 %s 到回收站 %s 失败：%v", path, finalRecyclePath, err)
	}

	addLog("info", fmt.Sprintf("文件 %s 已移动到回收站 %s（原因：在 temp_files.db 中不存在）", path, finalRecyclePath))
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

	localDBPath := "local_files.db"
	tempDBPath := "temp_files.db"
	scanListGzPath := filepath.Join(*media, ".scan.list.gz")

	for {
		syncStateMu.Lock()
		running := syncState.Running
		fromPathSync := syncState.FromPathSync
		if fromPathSync {
			syncState.FromPathSync = false
			syncStateMu.Unlock()
			addLog("info", "从路径同步完成，进入主同步等待状态")
			select {
			case <-syncState.Trigger:
				syncStateMu.Lock()
				syncState.Running = true
				syncState.LastStart = time.Now()
				syncStateMu.Unlock()
				addLog("info", "路径同步触发主同步，开始新一轮同步")
			case <-syncState.SyncDone:
				syncStateMu.Lock()
				syncState.Running = false
				syncStateMu.Unlock()
				addLog("info", "主同步任务暂停，等待触发")
				continue
			case <-time.After(100 * time.Millisecond):
				// 延迟处理定时器，避免干扰
				continue
			}
			continue
		}
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
		mediaDir := filepath.Clean(*media)
		if !testMediaFolder(mediaDir, paths) {
			addLog("warning", fmt.Sprintf("%s 不包含所有目标文件夹，将创建缺失的目录", mediaDir))
		}

		// 清理残留的 .tmp 文件
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

		// 检查本地数据库
		dbMu.Lock()
		if localDB == nil {
			var err error
			localDB, err = initLocalDB(localDBPath)
			if err != nil {
				dbMu.Unlock()
				addLog("error", fmt.Sprintf("初始化本地数据库失败：%v", err))
				continue
			}
		}
		dbMu.Unlock()

		if _, err := os.Stat(localDBPath); os.IsNotExist(err) {
			if err := scanLocalFiles(mediaDir, localDBPath); err != nil {
				addLog("error", fmt.Sprintf("生成本地数据库失败：%v", err))
				continue
			}
		}

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

		isSame, _, err := checkAndUpdateScanList(url, scanListGzPath)
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

		// 生成临时数据库
		if err := generateTempDB(scanListGzPath, tempDBPath); err != nil {
			addLog("error", fmt.Sprintf("生成临时数据库失败：%v", err))
			continue
		}

		// 删除 .scan.list.gz 文件
		if err := os.Remove(scanListGzPath); err != nil && !os.IsNotExist(err) {
			addLog("warning", fmt.Sprintf("删除数据包文件失败：%v", err))
		}

		// 比较数据库
		toUpdate, toDelete, err := compareAndPrepareSync(localDBPath, tempDBPath, paths)
		if err != nil {
			addLog("error", fmt.Sprintf("比较数据库失败：%v", err))
			continue
		}

		// 创建上下文以支持取消
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// 监听停止信号
		go func() {
			select {
			case <-syncState.StopPathSync:
				addLog("info", "接收到停止信号，终止主同步")
				cancel()
			case <-syncState.SyncDone:
				addLog("info", "主同步任务被停止")
				cancel()
			case <-ctx.Done():
			}
		}()

		// 执行同步
		successFiles, failedFiles, err := syncFilesCore(ctx, mediaDir, servers, toUpdate, toDelete, maxConcurrency, true)
		if err != nil && err != context.Canceled {
			addLog("error", fmt.Sprintf("核心同步失败：%v", err))
			continue
		}

		// 如果任务被取消，跳过清理
		if ctx.Err() != nil {
			addLog("info", fmt.Sprintf("主同步被终止，耗时 %s", formatDuration(time.Since(startTime))))
			continue
		}

		syncStateMu.Lock()
		if syncState.Running {
			if len(failedFiles) > 0 {
				addLog("warning", fmt.Sprintf("主同步完成，成功 %d 个文件，失败 %d 个文件，耗时 %s", len(successFiles), len(failedFiles), formatDuration(time.Since(startTime))))
			} else {
				addLog("success", fmt.Sprintf("主同步完成，成功 %d 个文件，耗时 %s", len(successFiles), formatDuration(time.Since(startTime))))
			}
			configMu.RLock()
			nextRun := time.Now().Add(time.Duration(config.Interval) * time.Hour)
			configMu.RUnlock()
			addLog("info", fmt.Sprintf("同步完成，进入等待状态，下次检测时间：%s", formatTime(nextRun)))
			syncState.LastStart = time.Now()
		}
		syncStateMu.Unlock()
	}
}

// syncFilesCore 执行文件同步核心逻辑
func syncFilesCore(ctx context.Context, mediaDir string, servers []ServerInfo, toUpdate []FileInfo, toDelete []string, maxConcurrency int, deleteFiles bool) ([]FileInfo, []string, error) {
	startTime := time.Now()
	addLog("info", fmt.Sprintf("开始核心同步，待更新 %d 个文件，待删除 %d 个文件", len(toUpdate), len(toDelete)))

	// 记录 toDelete 样本（如果数量较大）
	if len(toDelete) > 100 {
		sample := toDelete
		if len(sample) > 5 {
			sample = sample[:5]
		}
		addLog("info", fmt.Sprintf("toDelete 样本：%v", sample))
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrency)
	successFiles := make([]FileInfo, 0, len(toUpdate))
	failedFiles := make([]string, 0, len(toUpdate))
	var successMu, failedMu sync.Mutex
	deletedPaths := make([]string, 0, len(toDelete)) // 跟踪成功删除的路径
	var deletedMu sync.Mutex

	// 下载文件
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

	// 等待下载完成
	wg.Wait()

	// 删除文件（如果启用）
	if deleteFiles {
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
					} else {
						deletedMu.Lock()
						deletedPaths = append(deletedPaths, p)
						deletedMu.Unlock()
					}
				}(path)
			}
		}
	}

	// 等待删除完成
	wg.Wait()

	// 如果任务被取消，跳过数据库更新
	if ctx.Err() != nil {
		addLog("info", fmt.Sprintf("核心同步被终止，耗时 %s", formatDuration(time.Since(startTime))))
		return successFiles, failedFiles, ctx.Err()
	}

	// 更新本地数据库
	dbMu.Lock()
	if localDB == nil {
		dbMu.Unlock()
		return nil, nil, fmt.Errorf("本地数据库未初始化")
	}
	db := localDB
	dbMu.Unlock()

	tx, err := db.Beginx()
	if err != nil {
		return nil, nil, fmt.Errorf("启动本地数据库事务失败：%v", err)
	}

	// 插入或更新成功文件
	for _, file := range successFiles {
		_, err := tx.Exec(`INSERT OR REPLACE INTO files (path, timestamp) VALUES (?, ?)`, file.Path, file.Timestamp)
		if err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("批量更新数据库记录 %s 失败：%v", file.Path, err)
		}
	}

	// 删除成功移动的文件记录
	if deleteFiles {
		for _, path := range deletedPaths {
			_, err := tx.Exec(`DELETE FROM files WHERE path = ?`, path)
			if err != nil {
				tx.Rollback()
				return nil, nil, fmt.Errorf("批量删除数据库记录 %s 失败：%v", path, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("提交本地数据库事务失败：%v", err)
	}

	// 记录批量删除总结
	totalDeletes := len(toDelete)
	successDeletes := len(deletedPaths)
	failedDeletes := totalDeletes - successDeletes
	if totalDeletes > 0 {
		addLog("info", fmt.Sprintf("批量删除完成：共 %d 个文件，成功 %d 个，失败 %d 个", totalDeletes, successDeletes, failedDeletes))
	}

	// 不再更新 temp_files.db，保持全量数据
	addLog("success", fmt.Sprintf("核心同步完成，更新 %d 个文件，删除 %d 个文件，耗时 %s", len(successFiles), len(deletedPaths), formatDuration(time.Since(startTime))))
	return successFiles, failedFiles, nil
}

// checkAndUpdateScanList 检查并下载 .scan.list.gz 文件
func checkAndUpdateScanList(serverURL, localPath string) (bool, time.Time, error) {
	addLog("info", fmt.Sprintf("检查服务器 %s 数据包时间", serverURL))
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

	configMu.Lock()
	config.ScanListTime = serverTime
	configMu.Unlock()
	if err := saveConfig(); err != nil {
		addLog("error", fmt.Sprintf("更新配置文件时间失败：%v", err))
	}

	addLog("info", "数据包文件已更新")
	return false, serverTime, nil
}

// generateTempDB 从 .scan.list.gz 生成临时数据库
func generateTempDB(gzPath, tempDBPath string) error {
	addLog("info", fmt.Sprintf("开始生成临时数据库：%s（全量数据）", tempDBPath))
	startTime := time.Now()

	dbMu.Lock()
	if tempDB == nil {
		var err error
		tempDB, err = initLocalDB(tempDBPath)
		if err != nil {
			dbMu.Unlock()
			return fmt.Errorf("初始化临时数据库失败：%v", err)
		}
	}
	dbMu.Unlock()

	gzFile, err := os.Open(gzPath)
	if err != nil {
		return fmt.Errorf("打开数据包失败：%v", err)
	}
	defer gzFile.Close()

	gz, err := gzip.NewReader(gzFile)
	if err != nil {
		return fmt.Errorf("创建 gzip 读取器失败：%v", err)
	}
	defer gz.Close()

	scanner := bufio.NewScanner(gz)
	pattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2} /(.*)$`)

	var totalLines int
	pathCounts := make(map[string]int)
	configMu.RLock()
	sPathsAll := config.SPathsAll
	configMu.RUnlock()

	for scanner.Scan() {
		line := scanner.Text()
		match := pattern.FindStringSubmatch(line)
		if match != nil {
			filePath := match[1]
			for _, root := range sPathsAll {
				if strings.HasPrefix(filePath, root) {
					pathCounts[root]++
					break
				}
			}
			totalLines++
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("扫描数据包失败：%v", err)
	}

	configMu.Lock()
	if config.ServerPathCounts == nil {
		config.ServerPathCounts = make(map[string]int)
	}
	for _, root := range sPathsAll {
		config.ServerPathCounts[root] = pathCounts[root]
	}
	if err := saveConfig(); err != nil {
		addLog("error", fmt.Sprintf("保存服务器路径统计失败：%v", err))
	}
	configMu.Unlock()

	gzFile.Seek(0, io.SeekStart)
	gz, err = gzip.NewReader(gzFile)
	if err != nil {
		return fmt.Errorf("重新创建 gzip 读取器失败：%v", err)
	}
	defer gz.Close()
	scanner = bufio.NewScanner(gz)

	tx, err := tempDB.Beginx()
	if err != nil {
		return fmt.Errorf("启动事务失败：%v", err)
	}

	processedLines := 0
	var processedMu sync.Mutex
	lastProgress := -10

	for scanner.Scan() {
		line := scanner.Text()
		match := pattern.FindStringSubmatch(line)
		if match != nil {
			file := match[1]
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				timestampStr := parts[0] + " " + parts[1]
				t, err := time.Parse("2006-01-02 15:04", timestampStr)
				if err != nil {
					continue
				}
				_, err = tx.Exec(`INSERT OR REPLACE INTO files (path, timestamp) VALUES (?, ?)`, file, t.Unix())
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("插入文件记录失败：%v", err)
				}
			}
		}

		processedMu.Lock()
		processedLines++
		progress := int(float64(processedLines) / float64(totalLines) * 100)
		if progress >= lastProgress+10 {
			addLog("info", fmt.Sprintf("临时数据库生成进度：%d%% (%d/%d 条记录)", progress, processedLines, totalLines))
			lastProgress = progress - (progress % 10)
		}
		processedMu.Unlock()
	}

	if err := scanner.Err(); err != nil {
		tx.Rollback()
		return fmt.Errorf("扫描数据包失败：%v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败：%v", err)
	}

	addLog("success", fmt.Sprintf("临时数据库生成完成（全量数据），共 %d 条记录，耗时 %s", processedLines, formatDuration(time.Since(startTime))))
	return nil
}

// handleSyncPath 处理路径同步请求
func handleSyncPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		addLog("error", fmt.Sprintf("解析立即同步请求 JSON 失败：%v", err))
		http.Error(w, "解析JSON数据失败", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		addLog("error", "立即同步请求路径为空")
		http.Error(w, "路径不能为空", http.StatusBadRequest)
		return
	}

	addLog("info", fmt.Sprintf("接收到立即同步请求，路径：%s", req.Path))

	syncStateMu.Lock()
	if syncState.SyncingPath != "" {
		syncStateMu.Unlock()
		addLog("warning", fmt.Sprintf("已有同步任务（路径：%s），返回 busy", syncState.SyncingPath))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "busy"})
		return
	}
	syncState.SyncingPath = req.Path
	syncStateMu.Unlock()

	// 跟踪主同步触发状态
	mainSyncTriggered := false
	defer func() {
		syncStateMu.Lock()
		syncState.SyncingPath = ""
		// 仅当实际更新或同步被终止时触发主同步
		if mainSyncTriggered {
			syncState.FromPathSync = true
			select {
			case syncState.Trigger <- struct{}{}:
				addLog("info", "触发主同步等待循环")
			default:
				addLog("warning", "触发信号队列已满，主同步可能已在处理")
				mainSyncTriggered = false
			}
			configMu.RLock()
			nextRun := time.Now().Add(time.Duration(config.Interval) * time.Hour)
			configMu.RUnlock()
			addLog("info", fmt.Sprintf("路径同步完成，下一轮主同步计划时间：%s", formatTime(nextRun)))
		}
		addLog("info", fmt.Sprintf("路径 %s 同步任务结束", req.Path))
		syncStateMu.Unlock()
	}()

	mediaDir := flag.Lookup("media").Value.String()
	if mediaDir == "" {
		addLog("error", "未提供 --media 参数")
		http.Error(w, "未配置媒体目录", http.StatusInternalServerError)
		return
	}

	localDBPath := "local_files.db"
	tempDBPath := "temp_files.db"

	dbMu.Lock()
	if localDB == nil {
		var err error
		localDB, err = initLocalDB(localDBPath)
		if err != nil {
			dbMu.Unlock()
			addLog("error", fmt.Sprintf("初始化本地数据库失败：%v", err))
			http.Error(w, "初始化数据库失败", http.StatusInternalServerError)
			return
		}
	}
	if tempDB == nil {
		var err error
		tempDB, err = initLocalDB(tempDBPath)
		if err != nil {
			dbMu.Unlock()
			addLog("error", fmt.Sprintf("初始化临时数据库失败：%v", err))
			http.Error(w, "初始化数据库失败", http.StatusInternalServerError)
			return
		}
	}
	dbMu.Unlock()

	if _, err := os.Stat(tempDBPath); os.IsNotExist(err) {
		addLog("error", "临时数据库不存在，请先运行主同步")
		http.Error(w, "临时数据库不存在", http.StatusInternalServerError)
		return
	} else if err != nil {
		addLog("error", fmt.Sprintf("检查临时数据库失败：%v", err))
		http.Error(w, "检查临时数据库失败", http.StatusInternalServerError)
		return
	}

	addLog("info", fmt.Sprintf("查询本地数据库 %s 和临时数据库 %s，路径：%s", localDBPath, tempDBPath, req.Path))

	// 查询本地文件
	var localFiles []DBFileInfo
	err := localDB.Select(&localFiles, `SELECT path, timestamp FROM files WHERE path LIKE ?`, req.Path+"%")
	if err != nil {
		addLog("error", fmt.Sprintf("查询本地文件列表失败：%v", err))
		http.Error(w, "查询本地文件列表失败", http.StatusInternalServerError)
		return
	}

	// 查询服务器文件
	var serverFiles []DBFileInfo
	err = tempDB.Select(&serverFiles, `SELECT path, timestamp FROM files WHERE path LIKE ?`, req.Path+"%")
	if err != nil {
		addLog("error", fmt.Sprintf("查询服务器文件列表失败：%v", err))
		http.Error(w, "查询服务器文件列表失败", http.StatusInternalServerError)
		return
	}

	// 构建本地文件映射
	localMap := make(map[string]int64)
	for _, file := range localFiles {
		localMap[file.Path] = file.Timestamp
	}

	// 构建服务器文件映射
	serverMap := make(map[string]int64)
	for _, file := range serverFiles {
		serverMap[file.Path] = file.Timestamp
	}

	// 确定需要更新的文件
	var toUpdate []FileInfo
	for path, serverTimestamp := range serverMap {
		localTimestamp, exists := localMap[path]
		if !exists || time.Duration(serverTimestamp-localTimestamp)*time.Second > 10*time.Minute {
			toUpdate = append(toUpdate, FileInfo{Path: path, Timestamp: serverTimestamp})
		}
	}

	// 确定需要删除的文件
	var toDelete []string
	for path := range localMap {
		if _, exists := serverMap[path]; !exists {
			toDelete = append(toDelete, path)
		}
	}

	if len(toUpdate) == 0 && len(toDelete) == 0 {
		addLog("info", fmt.Sprintf("目录 %s 无待同步文件", req.Path))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"mainSyncTriggered": false,
			"message":           fmt.Sprintf("目录 %s 无需同步，无需触发主同步", req.Path),
		})
		return
	}

	configMu.RLock()
	servers := pickBestServers(config.SPool)
	maxConcurrency := config.MaxConcurrency
	configMu.RUnlock()
	if len(servers) == 0 {
		addLog("error", "没有可用的服务器")
		http.Error(w, "没有可用的服务器", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	go func() {
		select {
		case <-syncState.StopPathSync:
			addLog("info", fmt.Sprintf("接收到停止信号，终止路径 %s 同步", req.Path))
			cancel()
		case <-ctx.Done():
		}
	}()

	startTime := time.Now()
	addLog("info", fmt.Sprintf("开始同步目录 %s，待更新 %d 个文件，待删除 %d 个文件", req.Path, len(toUpdate), len(toDelete)))

	successFiles, failedFiles, err := syncFilesCore(ctx, mediaDir, servers, toUpdate, toDelete, maxConcurrency, true)
	if err != nil && err != context.Canceled {
		addLog("error", fmt.Sprintf("路径 %s 同步失败：%v", req.Path, err))
		http.Error(w, "同步失败", http.StatusInternalServerError)
		return
	}

	configMu.Lock()
	if config.PathUpdateNotices != nil && len(failedFiles) == 0 {
		delete(config.PathUpdateNotices, req.Path)
		if err := saveConfig(); err != nil {
			addLog("error", fmt.Sprintf("保存配置失败：%v", err))
		}
	}
	configMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	mainSyncTriggered = true // 标记需要触发主同步
	if ctx.Err() != nil {
		addLog("info", fmt.Sprintf("目录 %s 同步被用户终止，耗时 %s", req.Path, formatDuration(time.Since(startTime))))
		message := fmt.Sprintf("目录 %s 同步被终止，主同步%s触发", req.Path, map[bool]string{true: "已", false: "未"}[mainSyncTriggered])
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "stopped",
			"mainSyncTriggered": mainSyncTriggered,
			"message":           message,
		})
		return
	}

	duration := time.Since(startTime)
	if len(failedFiles) > 0 {
		addLog("warning", fmt.Sprintf("目录 %s 同步完成，成功 %d 个文件，失败 %d 个文件，耗时 %s", req.Path, len(successFiles), len(failedFiles), formatDuration(duration)))
		message := fmt.Sprintf("目录 %s 同步完成，成功 %d 个文件，失败 %d 个文件，主同步%s触发", req.Path, len(successFiles), len(failedFiles), map[bool]string{true: "已", false: "未"}[mainSyncTriggered])
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"mainSyncTriggered": mainSyncTriggered,
			"message":           message,
			"successCount":      len(successFiles),
			"failedCount":       len(failedFiles),
		})
	} else {
		addLog("success", fmt.Sprintf("目录 %s 同步完成，成功 %d 个文件，耗时 %s", req.Path, len(successFiles), formatDuration(duration)))
		message := fmt.Sprintf("目录 %s 同步完成，成功 %d 个文件，主同步%s触发", req.Path, len(successFiles), map[bool]string{true: "已", false: "未"}[mainSyncTriggered])
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"mainSyncTriggered": mainSyncTriggered,
			"message":           message,
			"successCount":      len(successFiles),
			"failedCount":       0,
		})
	}
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
	//mediaDir := flag.Lookup("media").Value.String()
	dbPath := "local_files.db" // 修改：修正为容器工作目录
	dbMu.Lock()
	if localDB == nil {
		var err error
		localDB, err = initLocalDB(dbPath)
		if err != nil {
			dbMu.Unlock()
			http.Error(w, "初始化数据库失败", http.StatusInternalServerError)
			return
		}
	}
	db := localDB // 新增：复用全局 localDB
	dbMu.Unlock()

	pathCounts := make(map[string]int)
	for _, path := range config.SPathsAll {
		var count int
		err := db.Get(&count, `SELECT COUNT(*) FROM files WHERE path LIKE ?`, path+"%")
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
	if syncState.SyncingPath != "" {
		message = fmt.Sprintf("同步目录 %s", syncState.SyncingPath)
	}
	json.NewEncoder(w).Encode(struct {
		IsRunning   bool   `json:"isRunning"`
		SyncingPath string `json:"syncingPath"`
		Message     string `json:"message"`
		NextRun     string `json:"nextRun"`
		Interval    int    `json:"interval"`
	}{
		IsRunning:   syncState.Running,
		SyncingPath: syncState.SyncingPath,
		Message:     message,
		NextRun:     nextRun,
		Interval:    config.Interval,
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
	if syncState.SyncingPath != "" {
		select {
		case syncState.StopPathSync <- struct{}{}:
			addLog("info", fmt.Sprintf("手动停止路径同步：%s", syncState.SyncingPath)) // 修改：在锁内调用
		default:
			addLog("warning", "路径同步停止信号队列已满") // 新增
		}
		syncState.SyncingPath = ""
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

func main() {
	// 初始化东八区时区
	var err error
	shanghaiLoc, err = time.LoadLocation("Asia/Shanghai")
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载时区失败：%v\n", err)
		os.Exit(1)
	}

	err = loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置文件失败：%v\n", err)
		os.Exit(1)
	}

	logsMu.Lock()
	logs = ring.New(config.LogSize) // 修改：使用 config.LogSize
	logsMu.Unlock()

	media := flag.String("media", "", "存储下载媒体文件的路径（必须）")
	flag.Parse()

	// 初始化数据库连接
	if *media != "" {
		localDBPath := "local_files.db"
		tempDBPath := "temp_files.db"
		dbMu.Lock()
		localDB, err = initLocalDB(localDBPath)
		if err != nil {
			dbMu.Unlock()
			fmt.Fprintf(os.Stderr, "初始化本地数据库失败：%v\n", err)
			os.Exit(1)
		}
		tempDB, err = initLocalDB(tempDBPath)
		if err != nil {
			localDB.Close()
			dbMu.Unlock()
			fmt.Fprintf(os.Stderr, "初始化临时数据库失败：%v\n", err)
			os.Exit(1)
		}
		dbMu.Unlock()
	}

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
	http.HandleFunc("/api/sync/path", handleSyncPath)
	http.HandleFunc("/api/config/get", handleConfigGet)
	http.HandleFunc("/api/refresh-local", handleRefreshLocal)
	http.Handle("/", fs)

	fmt.Fprintf(os.Stdout, "服务器启动，页面端口 :8080\n")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "服务器启动失败：%v\n", err)
		// 关闭数据库连接
		dbMu.Lock()
		if localDB != nil {
			localDB.Close()
			localDB = nil
		}
		if tempDB != nil {
			tempDB.Close()
			tempDB = nil
		}
		dbMu.Unlock()
		os.Exit(1)
	}
}
