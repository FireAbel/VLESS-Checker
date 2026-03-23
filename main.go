package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
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
	Timeout           time.Duration
	SkipTLSVerify     bool
	TryWSUpgrade      bool
	CustomSNI         string
	AllowInsecureWS   bool
	PreferWebsocket   bool
	TryVLESSHandshake bool
	ProbeDest         string
	ProbeHostHeader   string
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
		tryVLESS         bool
		probeDest        string
		probeHostHeader  string
	)

	flag.StringVar(&configURL, "config", "", "VLESS URL, e.g. vless://uuid@host:443?...")
	flag.IntVar(&timeoutSec, "timeout", 8, "stage timeout in seconds")
	flag.BoolVar(&skipTLSVerify, "skip-tls-verify", true, "skip TLS certificate verification")
	flag.BoolVar(&tryWS, "ws-probe", true, "attempt WebSocket HTTP upgrade probe for type=ws")
	flag.StringVar(&customSNI, "sni", "", "override SNI for TLS handshake")
	flag.BoolVar(&allowInsecureWS, "allow-insecure-ws", true, "allow ws probe over insecure TLS")
	flag.BoolVar(&preferWebsocket, "prefer-ws", true, "if network type unknown, still try ws probe")
	flag.BoolVar(&tryVLESS, "vless-handshake", true, "attempt real VLESS handshake and proxy probe")
	flag.StringVar(&probeDest, "probe-dest", "connectivitycheck.gstatic.com:80", "destination host:port for VLESS proxy probe")
	flag.StringVar(&probeHostHeader, "probe-host", "connectivitycheck.gstatic.com", "host header for HTTP probe over VLESS")
	flag.Parse()

	if configURL == "" {
		fmt.Fprintln(os.Stderr, "Ошибка: передайте VLESS-ссылку через --config")
		flag.Usage()
		os.Exit(2)
	}

	checkCfg := CheckConfig{
		Timeout:         time.Duration(timeoutSec) * time.Second,
		SkipTLSVerify:   skipTLSVerify,
		TryWSUpgrade:    tryWS,
		CustomSNI:       customSNI,
		AllowInsecureWS: allowInsecureWS,
		PreferWebsocket: preferWebsocket,
		TryVLESSHandshake: tryVLESS,
		ProbeDest:         probeDest,
		ProbeHostHeader:   probeHostHeader,
	}

	results, parsedCfg := RunChecks(configURL, checkCfg)
	printReport(parsedCfg, results)

	if hasFailure(results) {
		os.Exit(1)
	}
}

func RunChecks(raw string, cfg CheckConfig) ([]StageResult, *VLESSConfig) {
	results := make([]StageResult, 0, 10)

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
	resolvedIPs, err := resolveHost(parsed.Host, cfg.Timeout)
	detail := fmt.Sprintf("host=%s ips=%s", parsed.Host, strings.Join(resolvedIPs, ","))
	results = append(results, stageFrom("dns_resolve", start, err == nil, detail, err))
	if err != nil {
		return results, parsed
	}

	address := net.JoinHostPort(parsed.Host, parsed.Port)
	start = time.Now()
	conn, err := dialTCP(address, cfg.Timeout)
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
		tlsState, tlsErr := checkTLS(address, serverName, cfg.Timeout, cfg.SkipTLSVerify)
		results = append(results, stageFrom("tls_handshake", start, tlsErr == nil, tlsState, tlsErr))
		if tlsErr != nil {
			return results, parsed
		}
	}

	shouldTryWS := cfg.TryWSUpgrade && (strings.EqualFold(parsed.Type, "ws") || (parsed.Type == "" && cfg.PreferWebsocket))
	if shouldTryWS {
		start = time.Now()
		wsDetail, wsErr := probeWebSocket(parsed, cfg)
		results = append(results, stageFrom("ws_upgrade_probe", start, wsErr == nil, wsDetail, wsErr))
	}

	if cfg.TryVLESSHandshake {
		start = time.Now()
		hsDetail, hsErr := probeVLESSHandshake(parsed, cfg)
		results = append(results, stageFrom("vless_handshake", start, hsErr == nil, hsDetail, hsErr))
		if hsErr == nil {
			start = time.Now()
			postDetail, postErr := checkPostHandshakeBehavior(parsed, cfg)
			results = append(results, stageFrom("post_handshake_behavior", start, postErr == nil, postDetail, postErr))
		}
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
	}
	return cfg, nil
}

func resolveHost(host string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func dialTCP(address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.Dial("tcp", address)
}

func checkTLS(address, serverName string, timeout time.Duration, skipVerify bool) (string, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", address, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return fmt.Sprintf("version=%s cipher=%s sni=%s",
		tlsVersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), serverName), nil
}

func probeWebSocket(cfg *VLESSConfig, checkCfg CheckConfig) (string, error) {
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
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
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

func probeVLESSHandshake(cfg *VLESSConfig, checkCfg CheckConfig) (string, error) {
	dests := parseProbeDests(checkCfg.ProbeDest)
	var errs []string
	for _, dest := range dests {
		detail, err := probeVLESSHandshakeOnce(cfg, checkCfg, dest)
		if err == nil {
			return detail, nil
		}
		errs = append(errs, fmt.Sprintf("%s -> %v", dest, err))
	}
	return "", fmt.Errorf("VLESS handshake не прошел ни на одном --probe-dest: %s", strings.Join(errs, " | "))
}

func probeVLESSHandshakeOnce(cfg *VLESSConfig, checkCfg CheckConfig, probeDest string) (string, error) {
	conn, transportDetail, err := dialVLESSTransport(cfg, checkCfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	req, err := buildVLESSRequest(cfg.UUID, probeDest)
	if err != nil {
		return "", err
	}

	payload := []byte(fmt.Sprintf("HEAD /generate_204 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", checkCfg.ProbeHostHeader))

	isWS := strings.EqualFold(cfg.Type, "ws")
	if isWS {
		if err := wsWriteFrame(conn, 0x2, append(req, payload...)); err != nil {
			return transportDetail, fmt.Errorf("не удалось отправить VLESS через WS: %w", err)
		}
		serverData, err := wsReadFramePayload(conn, checkCfg.Timeout)
		if err != nil {
			return transportDetail, fmt.Errorf("не удалось прочитать WS frame с ответом: %w", err)
		}
		if len(serverData) < 2 {
			return transportDetail, fmt.Errorf("слишком короткий VLESS ответ через WS: %d байт", len(serverData))
		}
		respData, err := parseVLESSResponse(serverData)
		if err != nil {
			return transportDetail, err
		}
		return fmt.Sprintf("%s probe_dest=%s vless_ok=true ws_payload=%dB proxied_data=%dB", transportDetail, probeDest, len(serverData), len(respData)), nil
	}

	_ = conn.SetDeadline(time.Now().Add(checkCfg.Timeout))
	if _, err := conn.Write(append(req, payload...)); err != nil {
		return transportDetail, fmt.Errorf("не удалось отправить VLESS request: %w", err)
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return transportDetail, fmt.Errorf("не удалось прочитать заголовок VLESS ответа: %w", err)
	}
	if header[0] != 0 {
		return transportDetail, fmt.Errorf("неверная версия VLESS в ответе: 0x%x", header[0])
	}
	addonsLen := int(header[1])
	if addonsLen > 0 {
		dummy := make([]byte, addonsLen)
		if _, err := io.ReadFull(conn, dummy); err != nil {
			return transportDetail, fmt.Errorf("не удалось прочитать addons в VLESS ответе: %w", err)
		}
	}

	rest := make([]byte, 512)
	n, err := conn.Read(rest)
	if err != nil && !errors.Is(err, io.EOF) {
		return transportDetail, fmt.Errorf("не удалось прочитать проксированные данные после VLESS handshake: %w", err)
	}
	if n == 0 {
		return transportDetail, errors.New("VLESS handshake прошел, но проксированные данные не получены")
	}
	return fmt.Sprintf("%s probe_dest=%s vless_ok=true proxied_data=%dB", transportDetail, probeDest, n), nil
}

func checkPostHandshakeBehavior(cfg *VLESSConfig, checkCfg CheckConfig) (string, error) {
	dests := parseProbeDests(checkCfg.ProbeDest)
	var errs []string
	for _, dest := range dests {
		detail, err := checkPostHandshakeBehaviorOnce(cfg, checkCfg, dest)
		if err == nil {
			return detail, nil
		}
		errs = append(errs, fmt.Sprintf("%s -> %v", dest, err))
	}
	return "", fmt.Errorf("post-handshake поведение не подтверждено ни на одном --probe-dest: %s", strings.Join(errs, " | "))
}

func checkPostHandshakeBehaviorOnce(cfg *VLESSConfig, checkCfg CheckConfig, probeDest string) (string, error) {
	conn, transportDetail, err := dialVLESSTransport(cfg, checkCfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	req, err := buildVLESSRequest(cfg.UUID, probeDest)
	if err != nil {
		return "", err
	}

	isWS := strings.EqualFold(cfg.Type, "ws")
	if isWS {
		if err := wsWriteFrame(conn, 0x2, req); err != nil {
			return transportDetail, fmt.Errorf("не удалось отправить VLESS handshake через WS: %w", err)
		}
		serverData, err := wsReadFramePayload(conn, checkCfg.Timeout)
		if err != nil {
			return transportDetail, fmt.Errorf("не удалось прочитать WS frame с VLESS ответом: %w", err)
		}
		if _, err := parseVLESSResponse(serverData); err != nil {
			return transportDetail, err
		}
		return assessServerBehaviorWS(conn, fmt.Sprintf("%s probe_dest=%s", transportDetail, probeDest), behaviorProbeTimeout(checkCfg.Timeout))
	}

	_ = conn.SetDeadline(time.Now().Add(checkCfg.Timeout))
	if _, err := conn.Write(req); err != nil {
		return transportDetail, fmt.Errorf("не удалось отправить VLESS handshake: %w", err)
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return transportDetail, fmt.Errorf("не удалось прочитать VLESS ответ: %w", err)
	}
	if header[0] != 0 {
		return transportDetail, fmt.Errorf("неверная версия VLESS в ответе: 0x%x", header[0])
	}
	addonsLen := int(header[1])
	if addonsLen > 0 {
		dummy := make([]byte, addonsLen)
		if _, err := io.ReadFull(conn, dummy); err != nil {
			return transportDetail, fmt.Errorf("не удалось прочитать addons в VLESS ответе: %w", err)
		}
	}
	return assessServerBehaviorRaw(conn, fmt.Sprintf("%s probe_dest=%s", transportDetail, probeDest), behaviorProbeTimeout(checkCfg.Timeout))
}

func behaviorProbeTimeout(stageTimeout time.Duration) time.Duration {
	if stageTimeout <= 0 {
		return 2 * time.Second
	}
	t := stageTimeout / 3
	if t < time.Second {
		return time.Second
	}
	if t > 3*time.Second {
		return 3 * time.Second
	}
	return t
}

func assessServerBehaviorRaw(conn net.Conn, transportDetail string, wait time.Duration) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n > 0 {
		return fmt.Sprintf("%s behavior=data_received -> возможно OK", transportDetail), nil
	}
	if err == nil {
		return fmt.Sprintf("%s behavior=unexpected_empty_read", transportDetail), nil
	}
	if isTimeoutErr(err) {
		return fmt.Sprintf("%s behavior=hang_timeout(%s) -> возможно OK", transportDetail, wait), nil
	}
	if isConnResetErr(err) {
		return fmt.Sprintf("%s behavior=connection_reset -> auth fail", transportDetail), errors.New("после handshake соединение сброшено сервером (вероятно auth fail)")
	}
	if errors.Is(err, io.EOF) {
		return fmt.Sprintf("%s behavior=immediate_close -> reject", transportDetail), errors.New("после handshake сервер сразу закрыл соединение (reject)")
	}
	return fmt.Sprintf("%s behavior=read_error", transportDetail), fmt.Errorf("ошибка чтения после handshake: %w", err)
}

func assessServerBehaviorWS(conn net.Conn, transportDetail string, wait time.Duration) (string, error) {
	data, err := wsReadFramePayload(conn, wait)
	if err == nil {
		if len(data) > 0 {
			return fmt.Sprintf("%s behavior=ws_data_received -> возможно OK", transportDetail), nil
		}
		return fmt.Sprintf("%s behavior=ws_empty_frame", transportDetail), nil
	}
	if isTimeoutErr(err) {
		return fmt.Sprintf("%s behavior=hang_timeout(%s) -> возможно OK", transportDetail, wait), nil
	}
	if isConnResetErr(err) {
		return fmt.Sprintf("%s behavior=connection_reset -> auth fail", transportDetail), errors.New("после handshake соединение сброшено сервером (вероятно auth fail)")
	}
	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "close frame") || errors.Is(err, io.EOF) {
		return fmt.Sprintf("%s behavior=immediate_close -> reject", transportDetail), errors.New("после handshake сервер сразу закрыл WS соединение (reject)")
	}
	return fmt.Sprintf("%s behavior=ws_read_error", transportDetail), fmt.Errorf("ошибка чтения WS после handshake: %w", err)
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isConnResetErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") || strings.Contains(s, "forcibly closed")
}

func dialVLESSTransport(cfg *VLESSConfig, checkCfg CheckConfig) (net.Conn, string, error) {
	address := net.JoinHostPort(cfg.Host, cfg.Port)
	needsTLS := strings.EqualFold(cfg.Security, "tls") || strings.EqualFold(cfg.Security, "reality")

	var (
		conn net.Conn
		err  error
	)

	if needsTLS {
		serverName := cfg.SNI
		if checkCfg.CustomSNI != "" {
			serverName = checkCfg.CustomSNI
		}
		if serverName == "" {
			serverName = cfg.Host
		}
		d := &net.Dialer{Timeout: checkCfg.Timeout}
		conn, err = tls.DialWithDialer(d, "tcp", address, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: checkCfg.SkipTLSVerify,
			MinVersion:         tls.VersionTLS12,
		})
		if err != nil {
			return nil, "", fmt.Errorf("не удалось установить TLS транспорт для VLESS: %w", err)
		}
	} else {
		conn, err = dialTCP(address, checkCfg.Timeout)
		if err != nil {
			return nil, "", fmt.Errorf("не удалось установить TCP транспорт для VLESS: %w", err)
		}
	}

	if strings.EqualFold(cfg.Type, "ws") {
		if err := performWSUpgrade(conn, cfg); err != nil {
			_ = conn.Close()
			return nil, "", err
		}
		return conn, fmt.Sprintf("transport=ws endpoint=%s", address), nil
	}

	return conn, fmt.Sprintf("transport=tcp endpoint=%s", address), nil
}

func performWSUpgrade(conn net.Conn, cfg *VLESSConfig) error {
	wsPath := cfg.Path
	if wsPath == "" {
		wsPath = "/"
	}
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}
	hostHdr := cfg.HostHdr
	if hostHdr == "" {
		hostHdr = cfg.Host
	}

	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		return fmt.Errorf("не удалось сгенерировать WS key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyRaw)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: vless\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		wsPath, hostHdr, key)
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("ошибка отправки WS upgrade запроса: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return fmt.Errorf("ошибка чтения WS upgrade ответа: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("WS upgrade неуспешен: статус %d", resp.StatusCode)
	}
	return nil
}

func parseProbeDests(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return []string{"connectivitycheck.gstatic.com:80"}
	}
	return out
}

func buildVLESSRequest(uuidStr, dest string) ([]byte, error) {
	uuidRaw, err := decodeUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	targetHost, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, fmt.Errorf("некорректный --probe-dest (%s): %w", dest, err)
	}
	portNum, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 64)
	buf = append(buf, 0x00)       // version
	buf = append(buf, uuidRaw...) // user id
	buf = append(buf, 0x00)       // addons len
	buf = append(buf, 0x01)       // command tcp

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, portNum)
	buf = append(buf, portBytes...)

	if ip := net.ParseIP(targetHost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			v6 := ip.To16()
			if v6 == nil {
				return nil, fmt.Errorf("не удалось обработать IP адрес назначения: %s", targetHost)
			}
			buf = append(buf, 0x03)
			buf = append(buf, v6...)
		}
	} else {
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("слишком длинный домен в --probe-dest: %d", len(targetHost))
		}
		buf = append(buf, 0x02, byte(len(targetHost)))
		buf = append(buf, targetHost...)
	}

	return buf, nil
}

func parseVLESSResponse(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("слишком короткий ответ VLESS: %d байт", len(data))
	}
	if data[0] != 0 {
		return nil, fmt.Errorf("неверная версия VLESS в ответе: 0x%x", data[0])
	}
	addonsLen := int(data[1])
	if len(data) < 2+addonsLen {
		return nil, errors.New("ответ VLESS обрезан в области addons")
	}
	return data[2+addonsLen:], nil
}

func wsWriteFrame(conn net.Conn, opcode byte, payload []byte) error {
	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode) // FIN + opcode

	maskKey := make([]byte, 4)
	if _, err := rand.Read(maskKey); err != nil {
		return err
	}

	payloadLen := len(payload)
	switch {
	case payloadLen <= 125:
		header = append(header, 0x80|byte(payloadLen))
	case payloadLen <= 65535:
		header = append(header, 0x80|126)
		header = append(header, byte(payloadLen>>8), byte(payloadLen))
	default:
		header = append(header, 0x80|127)
		lenBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBuf, uint64(payloadLen))
		header = append(header, lenBuf...)
	}
	header = append(header, maskKey...)

	masked := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(masked)
	return err
}

func wsReadFramePayload(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	first := make([]byte, 2)
	if _, err := io.ReadFull(conn, first); err != nil {
		return nil, err
	}
	opcode := first[0] & 0x0F
	if opcode == 0x8 {
		return nil, errors.New("сервер закрыл WS соединение (close frame)")
	}
	masked := first[1]&0x80 != 0
	payloadLen := uint64(first[1] & 0x7F)
	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext))
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext)
	}
	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(conn, maskKey); err != nil {
			return nil, err
		}
	}
	if payloadLen > 2*1024*1024 {
		return nil, fmt.Errorf("слишком большой WS payload: %d", payloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return payload, nil
}

func decodeUUID(v string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(v), "-", "")
	if len(clean) != 32 {
		return nil, fmt.Errorf("некорректный UUID (ожидалось 32 hex символа): %s", v)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("некорректный UUID hex: %w", err)
	}
	return b, nil
}

func parsePort(v string) (uint16, error) {
	var p int
	if _, err := fmt.Sscanf(v, "%d", &p); err != nil {
		return 0, fmt.Errorf("некорректный порт: %s", v)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("порт вне диапазона: %d", p)
	}
	return uint16(p), nil
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
