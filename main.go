package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	outW io.Writer = os.Stdout
	errW io.Writer = os.Stderr
)

type StageResult struct {
	Name     string
	Success  bool
	Duration time.Duration
	Detail   string
	Err      error
}

type FailureInfo struct {
	Stage  string
	Code   string
	Reason string
}

type CheckConfig struct {
	Timeout         time.Duration
	SkipTLSVerify   bool
	TryWSUpgrade    bool
	CustomSNI       string
	AllowInsecureWS bool
	PreferWebsocket bool
	ProbeURL        string
	XrayTimeout     time.Duration
}

type VLESSConfig struct {
	Raw      string
	UUID     string
	Host     string
	Port     string
	SNI      string
	Security string
	Type     string
	Path     string
	HostHdr  string
	Flow     string
	FP       string
	PBK      string
	SID      string
}

func main() {
	var (
		configURL        string
		configURLHTTP    string
		logFile          string
		logDir           string
		timeoutSec       int
		skipTLSVerify    bool
		tryWS            bool
		customSNI        string
		allowInsecureWS  bool
		preferWebsocket  bool
		botMode          bool
		telegramToken    string
		maxConfigs       int
		workers          int
		botTimeoutSec    int
		userRPM          int
		globalRPM        int
		probeURL         string
		xrayTimeoutSec   int
		maxFromURL       int
		dbDir            string
		dbLogsDir        string
		dbWorkers        int
		dbMaxPerFile     int
		dbFileDelaySec   int
	)

	flag.StringVar(&configURL, "config", "", "VLESS URL, e.g. vless://uuid@host:443?...")
	flag.StringVar(&configURLHTTP, "config-url", "", "HTTP(S) URL that returns configs (text/base64/JSON containing vless://...)")
	flag.StringVar(&logFile, "log-file", "", "write CLI output to this file (in addition to stdout)")
	flag.StringVar(&logDir, "log-dir", "", "write CLI output to a timestamped file in this directory")
	flag.IntVar(&timeoutSec, "timeout", 8, "stage timeout in seconds")
	flag.BoolVar(&skipTLSVerify, "skip-tls-verify", true, "skip TLS certificate verification")
	flag.BoolVar(&tryWS, "ws-probe", true, "attempt WebSocket HTTP upgrade probe for type=ws")
	flag.StringVar(&customSNI, "sni", "", "override SNI for TLS handshake")
	flag.BoolVar(&allowInsecureWS, "allow-insecure-ws", true, "allow ws probe over insecure TLS")
	flag.BoolVar(&preferWebsocket, "prefer-ws", true, "if network type unknown, still try ws probe")
	flag.BoolVar(&botMode, "bot", false, "run as Telegram bot mode")
	flag.StringVar(&telegramToken, "telegram-token", "", "Telegram bot token (or env TELEGRAM_BOT_TOKEN)")
	flag.IntVar(&maxConfigs, "max-configs", 25, "max configs to check from one message")
	flag.IntVar(&workers, "workers", 8, "number of parallel workers for bot checks (5-10 recommended)")
	flag.IntVar(&botTimeoutSec, "bot-timeout", 30, "overall timeout in seconds for one dynamic config batch")
	flag.IntVar(&userRPM, "user-rpm", 60, "rate limit per user (checks per minute)")
	flag.IntVar(&globalRPM, "global-rpm", 300, "global rate limit (checks per minute)")
	flag.StringVar(&probeURL, "probe-url", "http://connectivitycheck.gstatic.com/generate_204", "HTTP probe URL for xray-based checks")
	flag.IntVar(&xrayTimeoutSec, "xray-timeout", 30, "overall timeout for embedded xray probe stage in seconds")
	flag.IntVar(&maxFromURL, "max-from-url", 25, "max configs to check when using --config-url")
	flag.StringVar(&dbDir, "db-dir", "", "папка с файлами конфигов (.txt и др.): проверка всех файлов, лог на каждый в --db-logs-dir")
	flag.StringVar(&dbLogsDir, "db-logs-dir", "", "куда писать логи (по умолчанию: <db-dir>/check_logs)")
	flag.IntVar(&dbWorkers, "db-workers", 3, "параллельных воркеров для --db-dir (xray тяжёлый, не завышайте)")
	flag.IntVar(&dbMaxPerFile, "db-max-per-file", 0, "макс. число vless из одного файла (0 = без лимита)")
	flag.IntVar(&dbFileDelaySec, "db-file-delay-sec", 30, "задержка между файлами в --db-dir (сек; 0 = без задержки)")
	flag.Parse()

	logCloser, logErr := setupLogWriters(logFile, logDir)
	if logErr != nil {
		fmt.Fprintln(os.Stderr, "Ошибка логирования:", logErr)
		os.Exit(2)
	}
	if logCloser != nil {
		defer logCloser()
	}

	checkCfg := CheckConfig{
		Timeout:         time.Duration(timeoutSec) * time.Second,
		SkipTLSVerify:   skipTLSVerify,
		TryWSUpgrade:    tryWS,
		CustomSNI:       customSNI,
		AllowInsecureWS: allowInsecureWS,
		PreferWebsocket: preferWebsocket,
		ProbeURL:        probeURL,
		XrayTimeout:     time.Duration(xrayTimeoutSec) * time.Second,
	}

	// Auto-bot mode: if no --config provided and a Telegram token exists,
	// start the bot without requiring --bot.
	if !botMode && strings.TrimSpace(configURL) == "" && strings.TrimSpace(configURLHTTP) == "" && strings.TrimSpace(dbDir) == "" {
		if strings.TrimSpace(telegramToken) == "" {
			telegramToken = os.Getenv("TELEGRAM_BOT_TOKEN")
		}
		if strings.TrimSpace(telegramToken) != "" {
			botMode = true
		}
	}

	if botMode {
		if telegramToken == "" {
			telegramToken = os.Getenv("TELEGRAM_BOT_TOKEN")
		}
		if telegramToken == "" {
			fmt.Fprintln(errW, "Ошибка: в режиме --bot нужен --telegram-token или переменная TELEGRAM_BOT_TOKEN")
			os.Exit(2)
		}
		if maxConfigs < 1 {
			maxConfigs = 1
		}
		if workers < 1 {
			workers = 1
		}
		if workers < 5 {
			workers = 5
		}
		if workers > 10 {
			workers = 10
		}
		if botTimeoutSec < 5 {
			botTimeoutSec = 5
		}
		if userRPM < 1 {
			userRPM = 1
		}
		if globalRPM < 1 {
			globalRPM = 1
		}
		if err := RunTelegramBot(telegramToken, checkCfg, BotConfig{
			MaxConfigs:   maxConfigs,
			Workers:      workers,
			BatchTimeout: time.Duration(botTimeoutSec) * time.Second,
			UserRPM:      userRPM,
			GlobalRPM:    globalRPM,
		}); err != nil {
			fmt.Fprintf(errW, "Ошибка запуска бота: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if strings.TrimSpace(configURLHTTP) != "" {
		if maxFromURL < 1 {
			maxFromURL = 1
		}
		text, err := downloadURLText(&http.Client{Timeout: 15 * time.Second}, configURLHTTP, 2*1024*1024)
		if err != nil {
			fmt.Fprintf(errW, "Ошибка: не удалось скачать --config-url: %v\n", err)
			os.Exit(1)
		}
		configs := ExtractVLESSConfigs(text)
		if len(configs) == 0 {
			fmt.Fprintln(errW, "Ошибка: в ответе --config-url не найдено vless:// конфигов")
			os.Exit(1)
		}
		if len(configs) > maxFromURL {
			configs = configs[:maxFromURL]
		}
		failAny := false
		statusLines := make([]string, 0, len(configs))
		for i, u := range configs {
			fmt.Fprintf(outW, "\n--- [%d/%d] %s ---\n", i+1, len(configs), u)
			results, parsedCfg := RunChecks(u, checkCfg)
			writeReport(outW, parsedCfg, results)
			label := configLabelFromURL(u, i+1)
			if hasFailure(results) {
				failAny = true
				fi, _ := failureInfoFromResults(results)
				line := fmt.Sprintf("STATUS %s error code=%s stage=%s reason=%s", label, fi.Code, fi.Stage, fi.Reason)
				statusLines = append(statusLines, line)
				fmt.Fprintln(outW, line)
			} else {
				line := fmt.Sprintf("STATUS %s ok code=OK", label)
				statusLines = append(statusLines, line)
				fmt.Fprintln(outW, line)
			}
		}
		sort.Strings(statusLines)
		fmt.Fprintln(outW, "\n=== Unified Statuses (--config-url) ===")
		for _, line := range statusLines {
			fmt.Fprintln(outW, line)
		}
		if failAny {
			os.Exit(1)
		}
		return
	}

	if strings.TrimSpace(dbDir) != "" {
		logsDir := strings.TrimSpace(dbLogsDir)
		if logsDir == "" {
			logsDir = filepath.Join(dbDir, "check_logs")
		}
		if dbWorkers < 1 {
			dbWorkers = 1
		}
		if dbFileDelaySec < 0 {
			dbFileDelaySec = 0
		}
		summary, err := RunDbDirectory(
			context.Background(),
			dbDir,
			logsDir,
			checkCfg,
			dbWorkers,
			dbMaxPerFile,
			time.Duration(dbFileDelaySec)*time.Second,
		)
		if err != nil {
			fmt.Fprintf(errW, "Ошибка --db-dir: %v\n", err)
			os.Exit(2)
		}
		okRate := 0.0
		if summary.ConfigsTotal > 0 {
			okRate = float64(summary.ConfigsOK) * 100 / float64(summary.ConfigsTotal)
		}
		fmt.Fprintf(outW, "\n=== db batch: готово ===\n"+
			"файлов: всего %d, успешных %d, проблемных %d\n"+
			"конфигов vless: проверено %d, успех %d, ошибка %d\n"+
			"логи: %s\nсводка: %s\n"+
			"\nКороткое саммари по проверенным конфигам:\n"+
			"- Всего: %d\n"+
			"- OK:    %d\n"+
			"- FAIL:  %d\n"+
			"- OK%%:   %.1f%%\n",
			summary.FilesTotal, summary.FilesOK, summary.FilesProblem,
			summary.ConfigsTotal, summary.ConfigsOK, summary.ConfigsFail,
			logsDir, summary.SummaryPath,
			summary.ConfigsTotal, summary.ConfigsOK, summary.ConfigsFail, okRate)
		if summary.FilesProblem > 0 {
			os.Exit(1)
		}
		return
	}

	if configURL == "" {
		fmt.Fprintln(errW, "Ошибка: передайте VLESS-ссылку через --config, или --config-url, или --db-dir, или используйте --bot")
		flag.Usage()
		os.Exit(2)
	}

	results, parsedCfg := RunChecks(configURL, checkCfg)
	writeReport(outW, parsedCfg, results)
	label := configLabelFromURL(configURL, 1)
	if fi, ok := failureInfoFromResults(results); ok {
		fmt.Fprintf(outW, "STATUS %s error code=%s stage=%s reason=%s\n", label, fi.Code, fi.Stage, fi.Reason)
	} else {
		fmt.Fprintf(outW, "STATUS %s ok code=OK\n", label)
	}

	if hasFailure(results) {
		os.Exit(1)
	}
}

func RunChecks(raw string, cfg CheckConfig) ([]StageResult, *VLESSConfig) {
	return RunChecksCtx(context.Background(), raw, cfg)
}

func RunChecksCtx(ctx context.Context, raw string, cfg CheckConfig) ([]StageResult, *VLESSConfig) {
	results := make([]StageResult, 0, 8)

	start := time.Now()
	parsed, err := ParseVLESS(raw)
	results = append(results, stageFrom("parse_config", start, err == nil, configSummary(parsed), err))
	if err != nil {
		return results, nil
	}
	if strings.EqualFold(parsed.Security, "reality") {
		results = append(results, StageResult{
			Name:     "reality_warning",
			Success:  true,
			Duration: 0,
			Detail:   "WARNING: security=reality может требовать shortId/publicKey/fingerprint. Эта утилита проверяет только базовую сетевую доступность и VLESS-обмен, не полный Reality-стек.",
		})
	}

	start = time.Now()
	resolvedIPs, err := resolveHost(ctx, parsed.Host, cfg.Timeout)
	detail := fmt.Sprintf("host=%s ips=%s", parsed.Host, strings.Join(resolvedIPs, ","))
	results = append(results, stageFrom("dns_resolve", start, err == nil, detail, err))
	if err != nil {
		return results, parsed
	}

	address := net.JoinHostPort(parsed.Host, parsed.Port)
	start = time.Now()
	conn, err := dialTCP(ctx, address, cfg.Timeout)
	results = append(results, stageFrom("tcp_connect", start, err == nil, address, err))
	if err != nil {
		return results, parsed
	}
	_ = conn.Close()

	needsTLS := strings.EqualFold(parsed.Security, "tls") || strings.EqualFold(parsed.Security, "reality")
	if needsTLS {
		serverName := parsed.SNI
		if cfg.CustomSNI != "" {
			serverName = cfg.CustomSNI
		}
		if serverName == "" {
			serverName = parsed.Host
		}

		start = time.Now()
		tlsState, tlsErr := checkTLS(ctx, address, serverName, cfg.Timeout, cfg.SkipTLSVerify)
		results = append(results, stageFrom("tls_handshake", start, tlsErr == nil, tlsState, tlsErr))
		if tlsErr != nil {
			return results, parsed
		}
	}

	shouldTryWS := cfg.TryWSUpgrade && (strings.EqualFold(parsed.Type, "ws") || (parsed.Type == "" && cfg.PreferWebsocket))
	if shouldTryWS {
		start = time.Now()
		wsDetail, wsErr := probeWebSocket(ctx, parsed, cfg)
		results = append(results, stageFrom("ws_upgrade_probe", start, wsErr == nil, wsDetail, wsErr))
	}

	netType := strings.ToLower(strings.TrimSpace(parsed.Type))
	if netType == "" {
		netType = "tcp"
	}
	if netType != "tcp" && netType != "ws" && netType != "xhttp" {
		results = append(results, StageResult{
			Name:     "xray_vless_proxy_probe_skipped",
			Success:  true,
			Duration: 0,
			Detail:   fmt.Sprintf("type=%s пока не поддержан в embedded xray-probe; этап proxy-probe пропущен. Базовые DNS/TCP/TLS проверки пройдены.", netType),
		})
		return results, parsed
	}

	// The decisive check: real proxying via embedded xray-core. This prevents
	// false positives where only DNS/TCP/TLS are OK but VLESS itself is not.
	start = time.Now()
	detail, xerr := probeVLESSViaXray(ctx, parsed, cfg)
	results = append(results, stageFrom("xray_vless_proxy_probe", start, xerr == nil, detail, xerr))
	if xerr != nil {
		return results, parsed
	}

	return results, parsed
}

func ParseVLESS(raw string) (*VLESSConfig, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("не удалось распарсить URL: %w", err)
	}
	if u.Scheme != "vless" {
		return nil, fmt.Errorf("ожидалась схема vless, получено: %s", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("UUID отсутствует в userinfo")
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, errors.New("в URL отсутствует host или port")
	}

	q := u.Query()
	cfg := &VLESSConfig{
		Raw:      raw,
		UUID:     u.User.Username(),
		Host:     u.Hostname(),
		Port:     u.Port(),
		SNI:      q.Get("sni"),
		Security: q.Get("security"),
		Type:     q.Get("type"),
		Path:     q.Get("path"),
		HostHdr:  q.Get("host"),
		Flow:     q.Get("flow"),
		FP:       q.Get("fp"),
		PBK:      q.Get("pbk"),
		SID:      firstNonEmpty(q.Get("sid"), q.Get("shortId"), q.Get("shortid")),
	}
	return cfg, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func resolveHost(ctx context.Context, host string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func dialTCP(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{}
	return d.DialContext(ctx, "tcp", address)
}

func checkTLS(ctx context.Context, address, serverName string, timeout time.Duration, skipVerify bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := &net.Dialer{}
	rawConn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return "", err
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	return fmt.Sprintf("version=%s cipher=%s sni=%s",
		tlsVersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), serverName), nil
}

func probeWebSocket(ctx context.Context, cfg *VLESSConfig, checkCfg CheckConfig) (string, error) {
	scheme := "http"
	if strings.EqualFold(cfg.Security, "tls") || strings.EqualFold(cfg.Security, "reality") {
		scheme = "https"
	}

	wsPath := cfg.Path
	if wsPath == "" {
		wsPath = "/"
	}
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}

	targetURL := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(cfg.Host, cfg.Port), wsPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}

	hostHdr := cfg.HostHdr
	if hostHdr == "" {
		hostHdr = cfg.Host
	}
	req.Host = hostHdr
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Protocol", "vless")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	client := &http.Client{
		Timeout: checkCfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: checkCfg.SkipTLSVerify && checkCfg.AllowInsecureWS,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		return fmt.Sprintf("status=%d (Switching Protocols), host_header=%s, path=%s", resp.StatusCode, hostHdr, wsPath), nil
	}

	return fmt.Sprintf("status=%d, host_header=%s, path=%s", resp.StatusCode, hostHdr, wsPath),
		fmt.Errorf("ожидался HTTP 101 для WS Upgrade, получено %d", resp.StatusCode)
}

func stageFrom(name string, start time.Time, success bool, detail string, err error) StageResult {
	return StageResult{
		Name:     name,
		Success:  success,
		Duration: time.Since(start),
		Detail:   detail,
		Err:      err,
	}
}

func writeReport(w io.Writer, cfg *VLESSConfig, results []StageResult) {
	fmt.Fprintln(w, "=== VLESS Connectivity Report ===")
	if cfg != nil {
		fmt.Fprintln(w, configSummary(cfg))
	}
	fmt.Fprintln(w)

	for _, r := range results {
		status := "OK"
		if !r.Success {
			status = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %-18s %v\n", status, r.Name, r.Duration.Round(time.Millisecond))
		if r.Detail != "" {
			fmt.Fprintf(w, "  detail: %s\n", r.Detail)
		}
		if r.Err != nil {
			fmt.Fprintf(w, "  error : %v\n", r.Err)
		}
	}

	if fail := firstFailure(results); fail != nil {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Итог: проблема возникает на этапе `%s`\n", fail.Name)
	} else {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Итог: базовая доступность подтверждена (все этапы успешны).")
	}
}

func setupLogWriters(logFile, logDir string) (func() error, error) {
	logFile = strings.TrimSpace(logFile)
	logDir = strings.TrimSpace(logDir)
	if logFile != "" && logDir != "" {
		return nil, errors.New("используйте только один из флагов: --log-file или --log-dir")
	}
	if logFile == "" && logDir == "" {
		return nil, nil
	}
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			return nil, err
		}
		logFile = filepath.Join(logDir, "run_"+time.Now().Format("20060102_150405")+".log")
	}
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	outW = io.MultiWriter(os.Stdout, f)
	errW = io.MultiWriter(os.Stderr, f)
	return f.Close, nil
}

func configSummary(cfg *VLESSConfig) string {
	if cfg == nil {
		return ""
	}
	security := cfg.Security
	if security == "" {
		security = "none"
	}
	networkType := cfg.Type
	if networkType == "" {
		networkType = "unknown"
	}
	return fmt.Sprintf("target=%s:%s security=%s type=%s sni=%s flow=%s",
		cfg.Host, cfg.Port, security, networkType, emptyAsDash(cfg.SNI), emptyAsDash(cfg.Flow))
}

func firstFailure(results []StageResult) *StageResult {
	for i := range results {
		if !results[i].Success {
			return &results[i]
		}
	}
	return nil
}

func failureInfoFromResults(results []StageResult) (FailureInfo, bool) {
	fail := firstFailure(results)
	if fail == nil {
		return FailureInfo{}, false
	}
	return normalizeFailure(fail.Name, fail.Err, fail.Detail), true
}

func normalizeFailure(stage string, err error, detail string) FailureInfo {
	src := strings.ToLower(strings.TrimSpace(detail))
	if err != nil {
		src = strings.ToLower(strings.TrimSpace(err.Error() + " | " + detail))
	}
	code := "UNKNOWN"
	reason := "неизвестная ошибка"
	switch {
	case strings.Contains(src, "no such host"):
		code, reason = "DNS_RESOLVE_FAILED", "домен не резолвится (DNS)"
	case strings.Contains(src, "connection refused"):
		code, reason = "TCP_CONNECTION_REFUSED", "порт закрыт (connection refused)"
	case strings.Contains(src, "i/o timeout"), strings.Contains(src, "context deadline exceeded"), strings.Contains(src, "timeout"):
		code, reason = "NETWORK_TIMEOUT", "таймаут сети/ответа"
	case strings.Contains(src, "connection reset"), strings.Contains(src, "forcibly closed"):
		code, reason = "CONNECTION_RESET", "соединение сброшено сервером"
	case strings.Contains(src, "tls"), strings.Contains(src, "handshake"):
		code, reason = "TLS_HANDSHAKE_FAILED", "ошибка TLS/Reality рукопожатия"
	case strings.Contains(src, "status=503"), strings.Contains(src, "получено 503"):
		code, reason = "PROBE_HTTP_503", "через прокси получен HTTP 503 на probe-url"
	case strings.Contains(src, "generate_204"), strings.Contains(src, "ожидался http 204"):
		code, reason = "PROBE_EXPECTED_204", "ожидался HTTP 204 на generate_204"
	case strings.Contains(src, "http probe вернул статус"):
		code, reason = "PROBE_HTTP_STATUS_BAD", "неподходящий HTTP-статус probe-url"
	case strings.Contains(src, "unsupported type"):
		code, reason = "UNSUPPORTED_TYPE", "неподдерживаемый тип транспорта"
	case strings.Contains(src, "unsupported security"):
		code, reason = "UNSUPPORTED_SECURITY", "неподдерживаемый security"
	case strings.Contains(src, "uuid"):
		code, reason = "INVALID_UUID", "некорректный UUID"
	}
	return FailureInfo{
		Stage:  stage,
		Code:   code,
		Reason: reason,
	}
}

func hasFailure(results []StageResult) bool {
	return firstFailure(results) != nil
}

func emptyAsDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func configLabelFromURL(link string, idx int) string {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return fmt.Sprintf("#config-%d", idx)
	}
	frag := strings.TrimSpace(u.Fragment)
	if frag == "" {
		return fmt.Sprintf("#config-%d", idx)
	}
	if dec, err := url.QueryUnescape(frag); err == nil {
		frag = strings.TrimSpace(dec)
	}
	if frag == "" {
		return fmt.Sprintf("#config-%d", idx)
	}
	if strings.HasPrefix(frag, "#") {
		return frag
	}
	return "#" + frag
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
