package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type StageResult struct {
	Name     string
	Success  bool
	Duration time.Duration
	Detail   string
	Err      error
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
	)

	flag.StringVar(&configURL, "config", "", "VLESS URL, e.g. vless://uuid@host:443?...")
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
	flag.Parse()

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
	if !botMode && strings.TrimSpace(configURL) == "" {
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
			fmt.Fprintln(os.Stderr, "Ошибка: в режиме --bot нужен --telegram-token или переменная TELEGRAM_BOT_TOKEN")
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
			fmt.Fprintf(os.Stderr, "Ошибка запуска бота: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if configURL == "" {
		fmt.Fprintln(os.Stderr, "Ошибка: передайте VLESS-ссылку через --config или используйте --bot")
		flag.Usage()
		os.Exit(2)
	}

	results, parsedCfg := RunChecks(configURL, checkCfg)
	printReport(parsedCfg, results)

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

	if strings.EqualFold(parsed.Security, "reality") && strings.EqualFold(parsed.Flow, "xtls-rprx-vision") {
		start = time.Now()
		detail, xerr := probeRealityVisionViaXray(ctx, parsed, cfg)
		results = append(results, stageFrom("xray_reality_vision_probe", start, xerr == nil, detail, xerr))
		if xerr != nil {
			return results, parsed
		}
	}

	shouldTryWS := cfg.TryWSUpgrade && (strings.EqualFold(parsed.Type, "ws") || (parsed.Type == "" && cfg.PreferWebsocket))
	if shouldTryWS {
		start = time.Now()
		wsDetail, wsErr := probeWebSocket(ctx, parsed, cfg)
		results = append(results, stageFrom("ws_upgrade_probe", start, wsErr == nil, wsDetail, wsErr))
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

func printReport(cfg *VLESSConfig, results []StageResult) {
	fmt.Println("=== VLESS Connectivity Report ===")
	if cfg != nil {
		fmt.Println(configSummary(cfg))
	}
	fmt.Println()

	for _, r := range results {
		status := "OK"
		if !r.Success {
			status = "FAIL"
		}
		fmt.Printf("[%s] %-18s %v\n", status, r.Name, r.Duration.Round(time.Millisecond))
		if r.Detail != "" {
			fmt.Printf("  detail: %s\n", r.Detail)
		}
		if r.Err != nil {
			fmt.Printf("  error : %v\n", r.Err)
		}
	}

	if fail := firstFailure(results); fail != nil {
		fmt.Println()
		fmt.Printf("Итог: проблема возникает на этапе `%s`\n", fail.Name)
	} else {
		fmt.Println()
		fmt.Println("Итог: базовая доступность подтверждена (все этапы успешны).")
	}
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

func hasFailure(results []StageResult) bool {
	return firstFailure(results) != nil
}

func emptyAsDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
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
