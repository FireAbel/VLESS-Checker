package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	_ "github.com/xtls/xray-core/main/json"
)

func probeVLESSViaXray(ctx context.Context, cfg *VLESSConfig, checkCfg CheckConfig) (string, error) {
	sec := strings.ToLower(stringsTrim(cfg.Security))
	if sec == "" {
		sec = "none"
	}
	netType := strings.ToLower(stringsTrim(cfg.Type))
	if netType == "" {
		netType = "tcp"
	}

	switch sec {
	case "none", "tls", "reality":
	default:
		return "", fmt.Errorf("xray-probe: unsupported security=%s", sec)
	}
	switch netType {
	case "tcp", "ws", "xhttp":
	default:
		return "", fmt.Errorf("xray-probe: unsupported type=%s", netType)
	}

	// Reality needs extra parameters.
	if sec == "reality" {
		if stringsTrim(cfg.PBK) == "" {
			return "", errors.New("reality: отсутствует pbk (public key) в ссылке")
		}
		if stringsTrim(cfg.SNI) == "" {
			return "", errors.New("reality: отсутствует sni в ссылке")
		}
		if stringsTrim(cfg.FP) == "" {
			return "", errors.New("reality: отсутствует fp (fingerprint) в ссылке")
		}
	}

	probeURL := checkCfg.ProbeURL
	if stringsTrim(probeURL) == "" {
		probeURL = "http://connectivitycheck.gstatic.com/generate_204"
	}
	if _, err := url.Parse(probeURL); err != nil {
		return "", fmt.Errorf("некорректный --probe-url: %w", err)
	}

	timeout := checkCfg.XrayTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	port, err := pickFreePort()
	if err != nil {
		return "", err
	}

	confBytes, err := buildXrayClientJSON(cfg, port, checkCfg.SkipTLSVerify)
	if err != nil {
		return "", err
	}

	inst, err := core.StartInstance("json", confBytes)
	if err != nil {
		return "", fmt.Errorf("xray start failed: %w", err)
	}
	defer inst.Close()
	if !inst.IsRunning() {
		if err := inst.Start(); err != nil {
			return "", fmt.Errorf("xray start() failed: %w", err)
		}
	}

	if err := waitPort(ctx, "127.0.0.1", port); err != nil {
		return "", fmt.Errorf("xray inbound not ready: %w", err)
	}

	start := time.Now()
	status, err := httpProbeViaHTTPProxy(ctx, port, probeURL)
	dur := time.Since(start).Round(time.Millisecond)
	if err != nil {
		return fmt.Sprintf("proxy=http://127.0.0.1:%d probe_url=%s dur=%s", port, probeURL, dur), classifyXrayProbeErr(err)
	}
	if probeExpectsGenerate204(probeURL) && status != http.StatusNoContent {
		return fmt.Sprintf("proxy=http://127.0.0.1:%d probe_url=%s status=%d dur=%s", port, probeURL, status, dur),
			fmt.Errorf("для generate_204 ожидался HTTP 204, получено %d — часто это captive portal/подмена ответа, а не рабочий выход в интернет через VLESS", status)
	}
	if status < 200 || status >= 400 {
		return fmt.Sprintf("proxy=http://127.0.0.1:%d probe_url=%s status=%d dur=%s", port, probeURL, status, dur),
			fmt.Errorf("HTTP probe вернул статус %d (ожидался 2xx/3xx) -> FAIL", status)
	}

	return fmt.Sprintf("proxy=http://127.0.0.1:%d probe_url=%s status=%d dur=%s", port, probeURL, status, dur), nil
}

// probeExpectsGenerate204: стандартные connectivity-check URL (Google) должны отвечать ровно 204.
// Любой 200/302 с «логином» провайдера иначе давал ложный OK.
func probeExpectsGenerate204(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	path := strings.ToLower(u.Path)
	if !strings.Contains(path, "generate_204") {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if strings.HasSuffix(h, ".gstatic.com") {
		return true
	}
	if h == "google.com" || strings.HasSuffix(h, ".google.com") {
		return true
	}
	return false
}

func buildVLESSUserJSON(uuid, flow string) map[string]any {
	u := map[string]any{
		"id":         uuid,
		"encryption": "none",
	}
	if stringsTrim(flow) != "" {
		u["flow"] = flow
	}
	return u
}

func buildXrayClientJSON(v *VLESSConfig, localHTTPProxyPort int, allowInsecureTLS bool) ([]byte, error) {
	remotePort, err := parsePortInt(v.Port)
	if err != nil {
		return nil, err
	}

	security := strings.ToLower(stringsTrim(v.Security))
	if security == "" {
		security = "none"
	}
	network := strings.ToLower(stringsTrim(v.Type))
	if network == "" {
		network = "tcp"
	}

	stream := map[string]any{
		"network":  network,
		"security": security,
	}
	if network == "ws" {
		wsPath := stringsTrim(v.Path)
		if wsPath == "" {
			wsPath = "/"
		}
		if !strings.HasPrefix(wsPath, "/") {
			wsPath = "/" + wsPath
		}
		host := stringsTrim(v.HostHdr)
		if host == "" {
			host = v.Host
		}
		stream["wsSettings"] = map[string]any{
			"path": wsPath,
			"headers": map[string]any{
				"Host": host,
			},
		}
	}
	if network == "xhttp" {
		xhttpPath := stringsTrim(v.Path)
		if xhttpPath == "" {
			xhttpPath = "/"
		}
		if !strings.HasPrefix(xhttpPath, "/") {
			xhttpPath = "/" + xhttpPath
		}
		host := stringsTrim(v.HostHdr)
		if host == "" {
			// Для xhttp предпочтительнее SNI, затем host из ссылки.
			host = stringsTrim(v.SNI)
		}
		if host == "" {
			host = v.Host
		}
		stream["xhttpSettings"] = map[string]any{
			"path": xhttpPath,
			"host": host,
			"mode": "auto",
		}
	}
	if security == "tls" {
		serverName := stringsTrim(v.SNI)
		if serverName == "" {
			serverName = v.Host
		}
		stream["tlsSettings"] = map[string]any{
			"serverName":    serverName,
			"allowInsecure": allowInsecureTLS,
		}
	}
	if security == "reality" {
		serverName := stringsTrim(v.SNI)
		if serverName == "" {
			serverName = v.Host
		}
		stream["realitySettings"] = map[string]any{
			"serverName":   serverName,
			"publicKey":    v.PBK,
			"shortId":      stringsTrim(v.SID),
			"fingerprint":  stringsTrim(v.FP),
			"show":         false,
			"spiderX":      "",
		}
	}

	// Minimal JSON config. We keep logs off to avoid noise in bot mode.
	// Inbound: local HTTP proxy.
	// Outbound: vless (tcp/ws/xhttp + none/tls/reality).
	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": "none",
		},
		"inbounds": []any{
			map[string]any{
				"tag":      "http-in",
				"listen":   "127.0.0.1",
				"port":     localHTTPProxyPort,
				"protocol": "http",
				"settings": map[string]any{
					"timeout": 0,
					"allowTransparent": false,
					"accounts":         []any{},
				},
			},
		},
		"outbounds": []any{
			map[string]any{
				"tag":      "proxy",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": v.Host,
							"port":    remotePort,
							"users": []any{
								buildVLESSUserJSON(v.UUID, v.Flow),
							},
						},
					},
				},
				"streamSettings": stream,
			},
			map[string]any{
				"tag":      "direct",
				"protocol": "freedom",
			},
			map[string]any{
				"tag":      "block",
				"protocol": "blackhole",
			},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{
					"type":        "field",
					"inboundTag":   []any{"http-in"},
					"outboundTag":  "proxy",
				},
			},
		},
	}

	return json.Marshal(cfg)
}

func httpProbeViaHTTPProxy(ctx context.Context, port int, target string) (int, error) {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func waitPort(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{}
	for {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func pickFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return 0, err
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return 0, err
	}
	return port, nil
}

func parsePortInt(v string) (int, error) {
	var p int
	if _, err := fmt.Sscanf(v, "%d", &p); err != nil {
		return 0, fmt.Errorf("некорректный порт: %s", v)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("порт вне диапазона: %d", p)
	}
	return p, nil
}

func stringsTrim(s string) string {
	return strings.TrimSpace(s)
}

func classifyXrayProbeErr(err error) error {
	if err == nil {
		return nil
	}
	// keep the message short but meaningful
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context deadline exceeded"):
		return errors.New("таймаут: xray-probe не успел получить ответ (возможен блок/неверные Reality параметры)")
	case strings.Contains(msg, "connection reset"), strings.Contains(msg, "forcibly closed"):
		return errors.New("соединение сброшено (reject/неверные Reality параметры/не тот inbound)")
	case strings.Contains(msg, "connection refused"):
		return errors.New("локальный прокси не поднялся (connection refused)")
	default:
		return err
	}
}

