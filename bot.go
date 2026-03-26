package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
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

type BotConfig struct {
	MaxConfigs   int
	Workers      int
	BatchTimeout time.Duration
	UserRPM      int
	GlobalRPM    int
}

type tokenBucket struct {
	mu        sync.Mutex
	capacity  float64
	tokens    float64
	refillPer float64 // tokens per second
	last      time.Time
}

func newTokenBucket(perMinute int, burst int) *tokenBucket {
	if perMinute < 1 {
		perMinute = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{
		capacity:  float64(burst),
		tokens:    float64(burst),
		refillPer: float64(perMinute) / 60.0,
		last:      time.Now(),
	}
}

func (b *tokenBucket) allowN(n int) bool {
	if n <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refillPer
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}

	need := float64(n)
	if b.tokens >= need {
		b.tokens -= need
		return true
	}
	return false
}

type botLimits struct {
	global  *tokenBucket
	perUser map[int64]*tokenBucket
	mu      sync.Mutex
}

func newBotLimits(userRPM, globalRPM int) *botLimits {
	return &botLimits{
		global:  newTokenBucket(globalRPM, globalRPM),
		perUser: map[int64]*tokenBucket{},
	}
}

func (l *botLimits) allow(chatID int64, checks int, userRPM int) bool {
	if !l.global.allowN(checks) {
		return false
	}
	l.mu.Lock()
	tb := l.perUser[chatID]
	if tb == nil {
		tb = newTokenBucket(userRPM, userRPM)
		l.perUser[chatID] = tb
	}
	l.mu.Unlock()
	return tb.allowN(checks)
}

type tgSendMessageResp struct {
	OK     bool            `json:"ok"`
	Result tgSendMsgResult `json:"result"`
}

type tgSendMsgResult struct {
	MessageID int `json:"message_id"`
	Chat      tgChat
	Text      string `json:"text"`
}

func RunTelegramBot(token string, checkCfg CheckConfig, cfg BotConfig) error {
	base := "https://api.telegram.org/bot" + token
	offset := 0
	client := &http.Client{Timeout: 30 * time.Second}
	limits := newBotLimits(cfg.UserRPM, cfg.GlobalRPM)
	batchSem := make(chan struct{}, 3) // limit parallel batches to avoid overload

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
			if err := handleUpdate(client, token, base, up, checkCfg, cfg, limits, batchSem); err != nil {
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

func handleUpdate(client *http.Client, token, base string, up tgUpdate, checkCfg CheckConfig, cfg BotConfig, limits *botLimits, batchSem chan struct{}) error {
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

	// If user sends an URL to a hosted config/subscription, download it and include into input.
	downloaded, hadURL, dlErr := downloadHTTPInputs(rawInput)
	if hadURL && dlErr != nil {
		return sendTelegramMessage(client, base, chatID, "Не удалось скачать конфиг по ссылке. Проверьте, что URL доступен без авторизации и отдает текст/base64.\nОшибка: "+dlErr.Error())
	}
	if strings.TrimSpace(downloaded) != "" {
		rawInput += "\n" + downloaded
	}

	configs := ExtractVLESSConfigs(rawInput)
	if len(configs) == 0 {
		return sendTelegramMessage(client, base, chatID, "VLESS конфиги не найдены. Проверьте формат входных данных.")
	}
	if len(configs) > cfg.MaxConfigs {
		configs = configs[:cfg.MaxConfigs]
	}

	if !limits.allow(chatID, len(configs), cfg.UserRPM) {
		return sendTelegramMessage(client, base, chatID, "Слишком много проверок. Подождите немного и попробуйте снова.")
	}

	batchSem <- struct{}{}
	defer func() { <-batchSem }()

	progressMsgID, err := sendTelegramMessageWithID(client, base, chatID, renderProgress(0, len(configs), "старт"))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.BatchTimeout)
	defer cancel()

	report, completed := buildConfigsReportParallel(ctx, configs, checkCfg, cfg.Workers, func(done int, total int, note string) {
		_ = editTelegramMessage(client, base, chatID, progressMsgID, renderProgress(done, total, note))
	})

	if !completed {
		report = "⚠️ Таймаут проверки пакета (30s). Отправляю частичный результат.\n\n" + report
	}
	_ = editTelegramMessage(client, base, chatID, progressMsgID, "Проверка завершена. Отправляю отчет…")
	return sendTelegramMessage(client, base, chatID, report)
}

type cfgResult struct {
	Idx    int
	Target string
	OK     bool
	Stage  string
	Reason string
}

func buildConfigsReportParallel(ctx context.Context, configs []string, checkCfg CheckConfig, workers int, onProgress func(done int, total int, note string)) (report string, completed bool) {
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan struct {
		idx int
		url string
	})
	resultsCh := make(chan cfgResult, len(configs))

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				res := checkOneConfig(ctx, job.idx, job.url, checkCfg)
				select {
				case resultsCh <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(resultsCh)
		wg.Wait()
	}()

	go func() {
		defer close(jobs)
		for i, u := range configs {
			select {
			case <-ctx.Done():
				return
			case jobs <- struct {
				idx int
				url string
			}{idx: i, url: u}:
			}
		}
	}()

	collected := make([]cfgResult, 0, len(configs))
	done := 0
	lastEdit := time.Now().Add(-10 * time.Second)

	for {
		select {
		case <-ctx.Done():
			// drain any ready results quickly
			for {
				select {
				case r, ok := <-resultsCh:
					if !ok {
						goto BUILD
					}
					collected = append(collected, r)
					done++
				default:
					goto BUILD
				}
			}
		case r, ok := <-resultsCh:
			if !ok {
				goto BUILD
			}
			collected = append(collected, r)
			done++
			if onProgress != nil && (time.Since(lastEdit) > 1*time.Second || done == len(configs)) {
				lastEdit = time.Now()
				onProgress(done, len(configs), "проверяю")
			}
		}
	}

BUILD:
	sort.Slice(collected, func(i, j int) bool { return collected[i].Idx < collected[j].Idx })
	lines := make([]string, 0, len(collected)*2+2)
	okCount := 0
	for _, r := range collected {
		if r.OK {
			okCount++
			lines = append(lines, fmt.Sprintf("%d) ✅ WORKS — %s", r.Idx+1, r.Target))
			continue
		}
		lines = append(lines, fmt.Sprintf("%d) ❌ FAIL — %s", r.Idx+1, r.Target))
		lines = append(lines, fmt.Sprintf("   этап: %s; причина: %s", r.Stage, r.Reason))
	}
	header := fmt.Sprintf("Итог: %d/%d работает. Проверено %d/%d.", okCount, len(collected), len(collected), len(configs))
	return ensureTelegramLimit(header + "\n\n" + strings.Join(lines, "\n")), len(collected) == len(configs)
}

func checkOneConfig(ctx context.Context, idx int, cfgURL string, checkCfg CheckConfig) cfgResult {
	results, parsed := RunChecksCtx(ctx, cfgURL, checkCfg)
	fail := firstFailure(results)
	target := cfgURL
	if parsed != nil {
		target = fmt.Sprintf("%s:%s (%s)", parsed.Host, parsed.Port, parsed.Type)
	}
	if fail == nil {
		return cfgResult{Idx: idx, Target: target, OK: true}
	}
	reason := shortReason(fail.Err)
	if reason == "" {
		reason = shortReasonText(fail.Detail)
	}
	if reason == "" {
		reason = "неизвестная причина"
	}
	return cfgResult{Idx: idx, Target: target, OK: false, Stage: fail.Name, Reason: reason}
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
	// If the dynamic config is JSON, extract embedded strings and try to
	// discover vless links / base64 payloads inside them.
	if extracted, ok := extractStringsFromJSON(input); ok {
		candidates = append(candidates, extracted...)
		for _, s := range extracted {
			if decoded, ok := decodeSubscriptionMaybe(s); ok {
				candidates = append(candidates, decoded)
			}
		}
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

func extractStringsFromJSON(input string) ([]string, bool) {
	trim := strings.TrimSpace(input)
	if trim == "" {
		return nil, false
	}
	// Cheap check to avoid attempting JSON parse on plain text.
	if !(strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[")) {
		return nil, false
	}
	var v any
	if err := json.Unmarshal([]byte(trim), &v); err != nil {
		return nil, false
	}
	var out []string
	collectStrings(v, &out)
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func collectStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s != "" {
			*out = append(*out, s)
		}
	case []any:
		for _, it := range t {
			collectStrings(it, out)
		}
	case map[string]any:
		for _, it := range t {
			collectStrings(it, out)
		}
	default:
		// ignore numbers/bools/null
	}
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

func downloadHTTPInputs(rawInput string) (downloaded string, hadURL bool, err error) {
	urls := findHTTPURLs(rawInput)
	if len(urls) == 0 {
		return "", false, nil
	}
	hadURL = true

	client := &http.Client{Timeout: 12 * time.Second}
	var out []string
	var errs []string
	for _, u := range urls {
		txt, e := downloadURLText(client, u, 2*1024*1024)
		if e != nil {
			errs = append(errs, fmt.Sprintf("%s -> %v", u, e))
			continue
		}
		if strings.TrimSpace(txt) != "" {
			out = append(out, txt)
		}
	}
	if len(out) == 0 {
		return "", true, fmt.Errorf("скачивание не удалось: %s", strings.Join(errs, " | "))
	}
	return strings.Join(out, "\n"), true, nil
}

func findHTTPURLs(rawInput string) []string {
	tokens := splitInputTokens(rawInput)
	urls := make([]string, 0, 4)
	seen := map[string]struct{}{}
	for _, t := range tokens {
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "http://") || strings.HasPrefix(lt, "https://") {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			urls = append(urls, t)
			if len(urls) >= 5 {
				break
			}
		}
	}
	return urls
}

func downloadURLText(client *http.Client, rawURL string, maxBytes int64) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("unsupported scheme")
	}
	// Remove URL fragment, it is not sent to server anyway.
	parsed.Fragment = ""
	rawURL = parsed.String()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "vless-checker-bot/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("status=%d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", err
	}
	return string(b), nil
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
	_, err := sendTelegramMessageWithID(client, base, chatID, text)
	return err
}

func sendTelegramMessageWithID(client *http.Client, base string, chatID int64, text string) (int, error) {
	form := url.Values{}
	form.Set("chat_id", fmt.Sprintf("%d", chatID))
	form.Set("text", text)
	form.Set("disable_web_page_preview", "true")

	resp, err := client.PostForm(base+"/sendMessage", form)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, fmt.Errorf("sendMessage status=%d body=%s", resp.StatusCode, string(b))
	}
	var decoded tgSendMessageResp
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return 0, err
	}
	if !decoded.OK {
		return 0, fmt.Errorf("sendMessage ok=false")
	}
	return decoded.Result.MessageID, nil
}

func editTelegramMessage(client *http.Client, base string, chatID int64, messageID int, text string) error {
	form := url.Values{}
	form.Set("chat_id", fmt.Sprintf("%d", chatID))
	form.Set("message_id", fmt.Sprintf("%d", messageID))
	form.Set("text", text)
	form.Set("disable_web_page_preview", "true")

	resp, err := client.PostForm(base+"/editMessageText", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("editMessageText status=%d body=%s", resp.StatusCode, string(b))
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

func renderProgress(done, total int, note string) string {
	if total <= 0 {
		total = 1
	}
	width := 16
	filled := int(float64(done) / float64(total) * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	bar := "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
	return fmt.Sprintf("%s %d/%d (%s)", bar, done, total, note)
}
