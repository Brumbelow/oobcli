package main

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainsCSV(t *testing.T) {
	cases := []struct {
		csv    string
		needle string
		want   bool
	}{
		{"http,dns,smtp", "dns", true},
		{" http , DNS ", "dns", true},
		{"http", "smtp", false},
	}
	for _, c := range cases {
		if got := containsCSV(c.csv, c.needle); got != c.want {
			t.Fatalf("containsCSV(%q,%q)=%v want %v", c.csv, c.needle, got, c.want)
		}
	}
}

func TestRandIDUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		id := randID()
		if _, ok := seen[id]; ok {
			t.Fatalf("randID produced duplicate: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestParseInteractshLine(t *testing.T) {
	// With full URL
	urlStr, domain := parseInteractshLine("Assigned: https://abc.oast.live")
	if urlStr == "" || domain != "abc.oast.live" {
		t.Fatalf("parseInteractshLine failed: url=%q domain=%q", urlStr, domain)
	}
	// With only domain pattern
	urlStr, domain = parseInteractshLine("server at xyz.oast.pro:8443 ready")
	if urlStr != "" || domain != "xyz.oast.pro" {
		t.Fatalf("parseInteractshLine domain-only failed: url=%q domain=%q", urlStr, domain)
	}
}

func TestWaitForLocalEvents(t *testing.T) {
	// Create a temp events file
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	testID := "test-12345"
	// Append line after a short delay
	go func() {
		time.Sleep(150 * time.Millisecond)
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		defer f.Close()
		w := bufio.NewWriter(f)
		w.WriteString("{\"id\":\"1\",\"marker\":\"" + testID + "\"}\n")
		w.Flush()
	}()
	ok := waitForLocalEvents(path, testID, time.Now().Add(2*time.Second))
	if !ok {
		t.Fatalf("waitForLocalEvents did not observe test id")
	}
}

func TestWebhookHasTestID_MapArray(t *testing.T) {
	m := map[string]any{
		"headers": map[string]any{
			"x-oob-test": []any{"foo", "bar", "test-abc"},
		},
	}
	if !webhookHasTestID(m, "test-abc") {
		t.Fatalf("expected webhookHasTestID to detect id in array header value")
	}
}

func TestDataDirAndSessionsDir(t *testing.T) {
	// Use XDG_DATA_HOME override
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tmp)
	dd, err := dataDir()
	if err != nil {
		t.Fatalf("dataDir: %v", err)
	}
	if !strings.HasPrefix(dd, tmp) {
		t.Fatalf("dataDir should use XDG_DATA_HOME: got %q not under %q", dd, tmp)
	}
	sd, err := sessionsDir()
	if err != nil {
		t.Fatalf("sessionsDir: %v", err)
	}
	if !strings.HasPrefix(sd, filepath.Join(tmp, "oobcli")) {
		t.Fatalf("sessionsDir path unexpected: %q", sd)
	}
}

func TestCreateWebhookInbox(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/token" {
			t.Fatalf("expected path /token, got %s", r.URL.Path)
		}
		if r.Header.Get("Api-Key") != "sekret" || r.Header.Get("X-Api-Key") != "sekret" {
			t.Fatalf("api key headers not set")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"uuid":"abc-123"}`))
	}))
	defer ts.Close()

	url, token, err := createWebhookInbox(ts.URL, "sekret")
	if err != nil {
		t.Fatalf("createWebhookInbox error: %v", err)
	}
	if token != "abc-123" {
		t.Fatalf("expected token abc-123, got %s", token)
	}
	wantURL := ts.URL + "/abc-123"
	if url != wantURL {
		t.Fatalf("expected url %s, got %s", wantURL, url)
	}
}

func TestEnsureWebhookURLPersists(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"uuid":"persist-1"}`))
	}))
	defer ts.Close()

	t.Setenv("WEBHOOK_SITE_API_BASE", ts.URL)
	meta := SessionMeta{ID: "s1", Provider: "webhook"}
	dir := t.TempDir()
	sessPath := filepath.Join(dir, "s1")
	if err := os.MkdirAll(sessPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	url, err := ensureWebhookURL(sessPath, &meta)
	if err != nil {
		t.Fatalf("ensureWebhookURL error: %v", err)
	}
	if url == "" || meta.ProviderKV["webhook_url"] != url {
		t.Fatalf("expected webhook_url to be set, got %q", url)
	}
	var stored SessionMeta
	if err := readJSON(metaPath(sessPath), &stored); err != nil {
		t.Fatalf("readJSON: %v", err)
	}
	if stored.ProviderKV["webhook_url"] != url {
		t.Fatalf("webhook_url not persisted; stored=%q url=%q", stored.ProviderKV["webhook_url"], url)
	}
}
