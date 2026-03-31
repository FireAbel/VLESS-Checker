package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"net/url"
)

// DbBatchSummary — итог прогона --db-dir.
type DbBatchSummary struct {
	FilesTotal    int
	FilesError    int // ошибка чтения исходника или создания .log
	FilesOK       int // файл обработан, есть vless, все конфиги прошли
	FilesProblem  int // нет vless, или есть FAIL по конфигам, или FilesError
	ConfigsTotal  int
	ConfigsOK     int
	ConfigsFail   int
	SummaryPath   string
	ConfigsOKPath string
	ConfigsErrPath string
}

type ConfigStatusRecord struct {
	Label string
	Link  string
	OK    bool
}

// RunDbDirectory читает все обычные файлы из dbDir (без вложенных папок),
// для каждого пишет отдельный .log в logsDir и общую сводку.
func RunDbDirectory(ctx context.Context, dbDir, logsDir string, checkCfg CheckConfig, workers, maxPerFile int, fileDelay time.Duration) (DbBatchSummary, error) {
	var sum DbBatchSummary
	start := time.Now()
	dbDir = filepath.Clean(dbDir)
	logsDir = filepath.Clean(logsDir)

	st, err := os.Stat(dbDir)
	if err != nil {
		return sum, fmt.Errorf("db-dir: %w", err)
	}
	if !st.IsDir() {
		return sum, fmt.Errorf("db-dir не является каталогом: %s", dbDir)
	}
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return sum, fmt.Errorf("db-logs-dir: %w", err)
	}

	files, err := listDbFlatFiles(dbDir)
	if err != nil {
		return sum, err
	}
	sum.FilesTotal = len(files)
	if sum.FilesTotal == 0 {
		sum.SummaryPath = filepath.Join(logsDir, "_summary.txt")
		var b strings.Builder
		fmt.Fprintf(&b, "время: %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(&b, "db-dir: %s\n", dbDir)
		fmt.Fprintf(&b, "общее время проверки: %s\n\n", time.Since(start).Round(time.Second))
		b.WriteString("=== Файлы ===\n")
		b.WriteString("Проверено файлов: 0\n")
		b.WriteString("  — успешных: 0\n")
		b.WriteString("  — проблемных: 0\n\n")
		b.WriteString("=== Конфиги vless (по всем файлам) ===\n")
		b.WriteString("Проверено конфигов: 0\n")
		b.WriteString("Успешных проверок: 0\n")
		b.WriteString("Неуспешных проверок: 0\n\n")
		b.WriteString("=== Список успешных файлов ===\n(пусто)\n\n")
		b.WriteString("=== Список проблемных файлов ===\n(пусто)\n")
		_ = os.WriteFile(sum.SummaryPath, []byte(b.String()), 0o644)
		return sum, nil
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	var filesErr atomic.Int32
	var cfgTotal, cfgOK, cfgFail atomic.Int32
	var doneFiles atomic.Int32
	var listMu sync.Mutex
	var termMu sync.Mutex
	var okFiles []string
	var problemFiles []string
	var configRecords []ConfigStatusRecord
	total := int32(len(files))
	progressEvery := int32(25)
	if total < 100 {
		progressEvery = 10
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for srcPath := range jobs {
				relpath, _ := filepath.Rel(dbDir, srcPath)
				if relpath == "." {
					relpath = filepath.Base(srcPath)
				}
				logName := dbLogFileName(srcPath) + ".log"
				logPath := filepath.Join(logsDir, logName)

				nRun, nOK, nFail, records, ferr := processOneDbFile(ctx, srcPath, logPath, relpath, checkCfg, maxPerFile, &termMu)
				cfgTotal.Add(int32(nRun))
				cfgOK.Add(int32(nOK))
				cfgFail.Add(int32(nFail))

				listMu.Lock()
				configRecords = append(configRecords, records...)
				if ferr != nil {
					filesErr.Add(1)
					problemFiles = append(problemFiles, fmt.Sprintf("%s — %v", relpath, ferr))
				} else if nRun == 0 {
					problemFiles = append(problemFiles, fmt.Sprintf("%s — в файле нет ни одной строки vless://", relpath))
				} else if nFail > 0 {
					problemFiles = append(problemFiles, fmt.Sprintf("%s — не прошли проверку %d из %d конфигов (OK %d)", relpath, nFail, nRun, nOK))
				} else {
					okFiles = append(okFiles, fmt.Sprintf("%s — конфигов: %d, все OK", relpath, nRun))
				}
				listMu.Unlock()

				n := doneFiles.Add(1)
				if n%progressEvery == 0 || n == total {
					fmt.Fprintf(errW, "db-dir: обработано файлов %d/%d\n", n, total)
				}
				// Пауза между файлами (настраивается через --db-file-delay-sec).
				if n < total && fileDelay > 0 {
					time.Sleep(fileDelay)
				}
			}
		}()
	}

	for _, p := range files {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	sum.FilesError = int(filesErr.Load())
	sum.ConfigsTotal = int(cfgTotal.Load())
	sum.ConfigsOK = int(cfgOK.Load())
	sum.ConfigsFail = int(cfgFail.Load())
	sum.FilesOK = len(okFiles)
	sum.FilesProblem = len(problemFiles)
	sum.SummaryPath = filepath.Join(logsDir, "_summary.txt")

	sort.Strings(okFiles)
	sort.Strings(problemFiles)
	sort.Slice(configRecords, func(i, j int) bool {
		return configRecords[i].Label < configRecords[j].Label
	})

	var b strings.Builder
	fmt.Fprintf(&b, "время: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "db-dir: %s\n", dbDir)
	fmt.Fprintf(&b, "общее время проверки: %s\n\n", time.Since(start).Round(time.Second))

	b.WriteString("=== Файлы ===\n")
	fmt.Fprintf(&b, "Проверено файлов: %d\n", sum.FilesTotal)
	fmt.Fprintf(&b, "  — успешных (есть vless, все конфиги прошли): %d\n", sum.FilesOK)
	fmt.Fprintf(&b, "  — проблемных (ошибка чтения/записи лога, нет vless или есть FAIL по конфигам): %d\n", sum.FilesProblem)
	if sum.FilesError > 0 {
		fmt.Fprintf(&b, "  — с ошибкой чтения исходного файла или создания .log: %d\n", sum.FilesError)
	}

	b.WriteString("\n=== Конфиги vless (по всем файлам) ===\n")
	fmt.Fprintf(&b, "Проверено конфигов: %d\n", sum.ConfigsTotal)
	fmt.Fprintf(&b, "Успешных проверок: %d\n", sum.ConfigsOK)
	fmt.Fprintf(&b, "Неуспешных проверок: %d\n", sum.ConfigsFail)

	b.WriteString("\n=== Список успешных файлов ===\n")
	if len(okFiles) == 0 {
		b.WriteString("(пусто)\n")
	} else {
		for _, line := range okFiles {
			fmt.Fprintf(&b, "  %s\n", line)
		}
	}

	b.WriteString("\n=== Список проблемных файлов ===\n")
	if len(problemFiles) == 0 {
		b.WriteString("(пусто)\n")
	} else {
		for _, line := range problemFiles {
			fmt.Fprintf(&b, "  %s\n", line)
		}
	}
	sum.ConfigsOKPath = filepath.Join(logsDir, "_configs_ok.txt")
	sum.ConfigsErrPath = filepath.Join(logsDir, "_configs_error.txt")
	if err := writeConfigStatusFiles(sum.ConfigsOKPath, sum.ConfigsErrPath, configRecords); err != nil {
		return sum, fmt.Errorf("файлы статусов конфигов: %w", err)
	}
	b.WriteString("\nфайлы со статусами конфигов:\n")
	fmt.Fprintf(&b, "  ok: %s\n", sum.ConfigsOKPath)
	fmt.Fprintf(&b, "  error: %s\n", sum.ConfigsErrPath)

	if err := os.WriteFile(sum.SummaryPath, []byte(b.String()), 0o644); err != nil {
		return sum, fmt.Errorf("сводка: %w", err)
	}
	termMu.Lock()
	fmt.Fprintf(outW, "\nФайлы статусов конфигов:\nok: %s\nerror: %s\n", sum.ConfigsOKPath, sum.ConfigsErrPath)
	termMu.Unlock()

	return sum, nil
}

func listDbFlatFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("чтение db-dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	return out, nil
}

func dbLogFileName(srcPath string) string {
	base := filepath.Base(srcPath)
	if base == "" || base == "." {
		return "config"
	}
	// точки в имя -> подчёркивания, чтобы 1.txt и 1.json не давали один 1.log
	stem := strings.ReplaceAll(base, ".", "_")
	// безопасное имя для Windows
	var sb strings.Builder
	for _, r := range stem {
		switch r {
		case '<', '>', ':', '"', '/', '\\', '|', '?', '*':
			sb.WriteRune('_')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func processOneDbFile(ctx context.Context, srcPath, logPath, relpath string, checkCfg CheckConfig, maxPerFile int, termMu *sync.Mutex) (nRun, nOK, nFail int, records []ConfigStatusRecord, err error) {
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("read: %w", err)
	}
	configs := ExtractVLESSConfigs(string(raw))
	if maxPerFile > 0 && len(configs) > maxPerFile {
		configs = configs[:maxPerFile]
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("log: %w", err)
	}
	defer f.Close()

	fmt.Fprintf(f, "=== файл: %s ===\n", relpath)
	fmt.Fprintf(f, "абсолютный путь: %s\n", srcPath)
	fmt.Fprintf(f, "время: %s\n\n", time.Now().Format(time.RFC3339))
	termMu.Lock()
	fmt.Fprintf(outW, "\n[db] файл: %s | найдено конфигов: %d\n", relpath, len(configs))
	termMu.Unlock()

	if len(configs) == 0 {
		fmt.Fprintln(f, "Итог: в файле не найдено ни одной строки vless://")
		return 0, 0, 0, nil, nil
	}

	for i, link := range configs {
		label := extractConfigLabel(link, i+1)
		fmt.Fprintf(f, "\n---------- конфиг [%d/%d] ----------\n", i+1, len(configs))
		termMu.Lock()
		fmt.Fprintf(outW, "[db] %s | конфиг %d/%d: запуск\n", relpath, i+1, len(configs))
		termMu.Unlock()
		results, parsedCfg := RunChecksCtx(ctx, link, checkCfg)
		writeReport(f, parsedCfg, results)
		nRun++
		if hasFailure(results) {
			nFail++
			records = append(records, ConfigStatusRecord{Label: label, Link: link, OK: false})
			fi, _ := failureInfoFromResults(results)
			termMu.Lock()
			fmt.Fprintf(outW, "[db] %s | конфиг %d/%d: STATUS %s error code=%s stage=%s reason=%s\n",
				relpath, i+1, len(configs), label, fi.Code, fi.Stage, fi.Reason)
			termMu.Unlock()
			fmt.Fprintf(f, "STATUS %s error code=%s stage=%s reason=%s\n", label, fi.Code, fi.Stage, fi.Reason)
		} else {
			nOK++
			records = append(records, ConfigStatusRecord{Label: label, Link: link, OK: true})
			termMu.Lock()
			fmt.Fprintf(outW, "[db] %s | конфиг %d/%d: STATUS %s ok code=OK\n", relpath, i+1, len(configs), label)
			termMu.Unlock()
			fmt.Fprintf(f, "STATUS %s ok code=OK\n", label)
		}
	}

	fmt.Fprintf(f, "\n=== сводка по файлу: проверено %d, OK %d, FAIL %d ===\n", nRun, nOK, nFail)
	return nRun, nOK, nFail, records, nil
}

func extractConfigLabel(link string, idx int) string {
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

func writeConfigStatusFiles(okPath, errPath string, records []ConfigStatusRecord) error {
	var okLines []string
	var errLines []string
	for _, r := range records {
		line := strings.TrimSpace(r.Link)
		if line == "" {
			continue
		}
		if r.OK {
			okLines = append(okLines, line)
		} else {
			errLines = append(errLines, line)
		}
	}
	if len(okLines) == 0 {
		okLines = []string{"(пусто)"}
	}
	if len(errLines) == 0 {
		errLines = []string{"(пусто)"}
	}
	if err := os.WriteFile(okPath, []byte(strings.Join(okLines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(errPath, []byte(strings.Join(errLines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}
