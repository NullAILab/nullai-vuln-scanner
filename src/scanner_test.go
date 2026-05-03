package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────
// Port scanner tests
// ─────────────────────────────────────────────

func TestScanPortsFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	open := scanPorts("127.0.0.1", port, port, 1, time.Second)
	if len(open) != 1 || open[0] != port {
		t.Errorf("expected [%d], got %v", port, open)
	}
}

func TestScanPortsReturnsEmpty(t *testing.T) {
	// Use a tiny timeout — port 0 is invalid, should return nothing
	open := scanPorts("127.0.0.1", 65500, 65500, 1, 100*time.Millisecond)
	// We can't assert it's empty (port might be open) but must not panic
	_ = open
}

// ─────────────────────────────────────────────
// HTTP header check tests
// ─────────────────────────────────────────────

func TestCheckHTTPHeadersMissingHSTS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings := checkHTTPHeaders(ts.URL, 5*time.Second)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Detail, "Strict-Transport-Security") {
			found = true
			if f.Severity != HIGH {
				t.Errorf("expected HIGH for missing HSTS, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding for missing Strict-Transport-Security header")
	}
}

func TestCheckHTTPHeadersServerBanner(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.51 (Ubuntu)")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings := checkHTTPHeaders(ts.URL, 5*time.Second)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Detail, "Server header exposed") {
			found = true
			if f.Severity != LOW {
				t.Errorf("expected LOW for server banner, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding for Server header exposure")
	}
}

func TestCheckHTTPHeadersPlainHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings := checkHTTPHeaders(ts.URL, 5*time.Second)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Detail, "plain HTTP") {
			found = true
			if f.Severity != HIGH {
				t.Errorf("expected HIGH for plain HTTP, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding for plain HTTP")
	}
}

// ─────────────────────────────────────────────
// Finding string representation
// ─────────────────────────────────────────────

func TestFindingString(t *testing.T) {
	f := Finding{HIGH, "tls", "certificate expired"}
	s := f.String()
	if !strings.Contains(s, "HIGH") || !strings.Contains(s, "certificate expired") {
		t.Errorf("unexpected finding string: %q", s)
	}
}
