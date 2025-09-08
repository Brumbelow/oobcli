package main

import (
    "bufio"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

func TestContainsCSV(t *testing.T) {
    cases := []struct{
        csv string
        needle string
        want bool
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

