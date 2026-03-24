package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type tgUpdateResp struct {
	OK     bool       `json:"ok"`
	Result []tgUpdate `json:"result"`
}

type tgUpdate struct {
	UpdateID int       `json:"update_id"`
	Message  tgMessage `json:"message"`
}

type tgMessage struct {
	Chat     tgChat     `json:"chat"`
	Text     string     `json:"text"`
	Caption  string     `json:"caption"`
	Document tgDocument `json:"document"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgDocument struct {
	FileID string `json:"file_id"`
}

type tgGetFileResp struct {
	OK     bool       `json:"ok"`
	Result tgFileInfo `json:"result"`
}

type tgFileInfo struct {
	FilePath string `json:"file_path"`
}

func RunTelegramBot(token string, checkCfg CheckConfig, maxConfigs int) error {
	base := "https://api.telegram.org/bot" + token
	offset := 0
	client := &http.Client{Timeout: 30 * time.Second}

	fmt.Println("Telegram bot started. Waiting for messages...")
	for {
		updates, err := getTelegramUpdates(client, base, offset)
		if err != nil {
			fmt.Fprintf(os.Stderr, "getUpdates error: %v\n", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, up := range updates {
			if up.UpdateID >= offset {
				offset = up.UpdateID + 1
			}
			if up.Message.Chat.ID == 0 {
				continue
			}
			if err := handleUpdate(client, token, base, up, checkCfg, maxConfigs); err != nil {
				_ = sendTelegramMessage(client, base, up.Message.Chat.ID, "Ошибка обработки: "+err.Error())
			}
		}
	}
}

func getTelegramUpdates(client *http.Client, base string, offset int) ([]tgUpdate, error) {
	u := fmt.Sprintf("%s/getUpdates?timeout=25&offset=%d", base, offset)
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("telegram status=%d body=%s", resp.StatusCode, string(b))
	}
	var decoded tgUpdateResp
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	if !decoded.OK {
		return nil, fmt.Errorf("telegram api returned ok=false")
	}
	return decoded.Result, nil
}

func handleUpdate(client *http.Client, token, base string, up tgUpdate, checkCfg CheckConfig, maxConfigs int) error {
	chatID := up.Message.Chat.ID
	rawInput := strings.TrimSpace(up.Message.Text)
	if rawInput == "" {
		rawInput = strings.TrimSpace(up.Message.Caption)
	}
	if up.Message.Document.FileID != "" {
		fileText, err := downloadTelegramFileText(client, token, up.Message.Document.FileID)
		if err != nil {
			return fmt.Errorf("не удалось скачать файл: %w", err)
		}
		if rawInput != "" {
			rawInput += "\n" + fileText
		} else {
			rawInput = fileText
		}
	}
	if rawInput == "" {
		return sendTelegramMessage(client, base, chatID, "Отправьте текст/файл с динамическим конфигом (vless://... или base64 подписка).")
	}

	configs := ExtractVLESSConfigs(rawInput)
	if len(configs) == 0 {
		return sendTelegramMessage(client, base, chatID, "VLESS конфиги не найдены. Проверьте формат входных данных.")
	}
	if len(configs) > maxConfigs {
		configs = configs[:maxConfigs]
	}

	_ = sendTelegramMessage(client, base, chatID, fmt.Sprintf("Найдено %d конфиг(ов). Запускаю проверку...", len(configs)))
	report := buildConfigsReport(configs, checkCfg)
	return sendTelegramMessage(client, base, chatID, report)
}

func buildConfigsReport(configs []string, checkCfg CheckConfig) string {
	lines := make([]string, 0, len(configs)+2)
	okCount := 0
	for i, cfgURL := range configs {
		results, parsed := RunChecks(cfgURL, checkCfg)
		fail := firstFailure(results)
		target := cfgURL
		if parsed != nil {
			target = fmt.Sprintf("%s:%s (%s)", parsed.Host, parsed.Port, parsed.Type)
		}
		if fail == nil {
			okCount++
			lines = append(lines, fmt.Sprintf("%d) ✅ WORKS — %s", i+1, target))
			continue
		}
		reason := shortReason(fail.Err)
		if reason == "" {
			reason = shortReasonText(fail.Detail)
		}
		if reason == "" {
			reason = "неизвестная причина"
		}
		lines = append(lines, fmt.Sprintf("%d) ❌ FAIL — %s", i+1, target))
		lines = append(lines, fmt.Sprintf("   этап: %s; причина: %s", fail.Name, reason))
	}
	header := fmt.Sprintf("Итог: %d/%d работает.", okCount, len(configs))
	return ensureTelegramLimit(header + "\n\n" + strings.Join(lines, "\n"))
}

func shortReason(err error) string {
	if err == nil {
		return ""
	}
	return shortReasonText(err.Error())
}

func shortReasonText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "no such host"):
		return "домен не резолвится (DNS)"
	case strings.Contains(l, "i/o timeout"), strings.Contains(l, "timeout"):
		return "таймаут соединения/ответа"
	case strings.Contains(l, "connection refused"):
		return "порт закрыт (connection refused)"
	case strings.Contains(l, "connection reset"), strings.Contains(l, "forcibly closed"):
		return "соединение сброшено сервером"
	case strings.Contains(l, "unexpected eof"), strings.Contains(l, "eof"):
		return "сервер закрыл соединение"
	case strings.Contains(l, "ws upgrade"), strings.Contains(l, "101"):
		return "ошибка WebSocket upgrade"
	case strings.Contains(l, "uuid"):
		return "некорректный UUID"
	default:
		if len(s) > 140 {
			return s[:140] + "..."
		}
		return s
	}
}

func ExtractVLESSConfigs(input string) []string {
	candidates := []string{input}
	if decoded, ok := decodeSubscriptionMaybe(input); ok {
		candidates = append(candidates, decoded)
	}

	seen := map[string]struct{}{}
	var out []string
	for _, c := range candidates {
		for _, token := range splitInputTokens(c) {
			if !strings.HasPrefix(strings.ToLower(token), "vless://") {
				continue
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}
	sort.Strings(out)
	return out
}

func splitInputTokens(s string) []string {
	replacer := strings.NewReplacer("\r", "\n", "\t", "\n", " ", "\n", ",", "\n", ";", "\n", "\"", "\n", "'", "\n")
	s = replacer.Replace(s)
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		v := strings.TrimSpace(r)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func decodeSubscriptionMaybe(input string) (string, bool) {
	s := strings.TrimSpace(input)
	if strings.Contains(strings.ToLower(s), "vless://") {
		return "", false
	}
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if s == "" {
		return "", false
	}

	// try standard and URL-safe base64.
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		b, err := dec(s)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(b))
		if strings.Contains(strings.ToLower(text), "vless://") {
			return text, true
		}
	}
	return "", false
}

func downloadTelegramFileText(client *http.Client, token, fileID string) (string, error) {
	getFileURL := fmt.Sprintf("https://api.telegram.org/bot%s/getFile?file_id=%s", token, url.QueryEscape(fileID))
	resp, err := client.Get(getFileURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("getFile status=%d", resp.StatusCode)
	}
	var decoded tgGetFileResp
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", err
	}
	if !decoded.OK || decoded.Result.FilePath == "" {
		return "", fmt.Errorf("telegram getFile returned empty path")
	}
	fileURL := fmt.Sprintf("https://api.telegram.org/file/bot%s/%s", token, decoded.Result.FilePath)
	fileResp, err := client.Get(fileURL)
	if err != nil {
		return "", err
	}
	defer fileResp.Body.Close()
	if fileResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("file download status=%d", fileResp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(fileResp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func sendTelegramMessage(client *http.Client, base string, chatID int64, text string) error {
	form := url.Values{}
	form.Set("chat_id", fmt.Sprintf("%d", chatID))
	form.Set("text", text)
	form.Set("disable_web_page_preview", "true")

	resp, err := client.PostForm(base+"/sendMessage", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("sendMessage status=%d body=%s", resp.StatusCode, string(b))
	}
	return nil
}

func ensureTelegramLimit(s string) string {
	const maxLen = 3900
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (report truncated)"
}
