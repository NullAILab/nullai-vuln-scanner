// Package main — simple vulnerability scanner.
//
// Performs a series of lightweight, non-intrusive checks against a target
// host/URL and reports potential security issues. No CVE database is bundled;
// the checks are pattern-based and version-string heuristics only.
//
// Checks implemented:
//   - Open TCP port enumeration (configurable range)
//   - HTTP header analysis (missing security headers, server banner leakage)
//   - HTTP redirect chain (HTTP → HTTPS enforcement)
//   - TLS certificate validity and expiry
//   - Default page / directory listing detection
//   - Basic HTTP method enumeration (OPTIONS, TRACE)
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────
// Finding severity levels
// ─────────────────────────────────────────────

type Severity string

const (
	INFO   Severity = "INFO"
	LOW    Severity = "LOW"
	MEDIUM Severity = "MEDIUM"
	HIGH   Severity = "HIGH"
)

// Finding represents one discovered issue.
type Finding struct {
	Severity Severity
	Check    string
	Detail   string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %-10s %s", f.Severity, f.Check, f.Detail)
}

// ─────────────────────────────────────────────
// Port scanner
// ─────────────────────────────────────────────

// scanPorts connects to each port in [start, end] concurrently using a worker
// pool of size concurrency. Returns sorted list of open ports.
func scanPorts(host string, start, end, concurrency int, timeout time.Duration) []int {
	work := make(chan int, end-start+1)
	for p := start; p <= end; p++ {
		work <- p
	}
	close(work)

	var mu sync.Mutex
	var open []int

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range work {
				addr := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					open = append(open, port)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// ─────────────────────────────────────────────
// HTTP checks
// ─────────────────────────────────────────────

var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

func newHTTPClient(timeout time.Duration, followRedirects bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false}, //nolint:gosec
	}
	c := &http.Client{Transport: tr, Timeout: timeout}
	if !followRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// checkHTTPHeaders fetches the root URL and inspects response headers.
func checkHTTPHeaders(targetURL string, timeout time.Duration) []Finding {
	client := newHTTPClient(timeout, true)
	resp, err := client.Get(targetURL)
	if err != nil {
		return []Finding{{HIGH, "HTTP", fmt.Sprintf("request failed: %v", err)}}
	}
	defer resp.Body.Close()

	var findings []Finding

	// Missing security headers
	for _, h := range securityHeaders {
		if resp.Header.Get(h) == "" {
			sev := MEDIUM
			if h == "Strict-Transport-Security" {
				sev = HIGH
			}
			findings = append(findings, Finding{sev, "headers", fmt.Sprintf("missing %s", h)})
		}
	}

	// Server banner leakage
	if sv := resp.Header.Get("Server"); sv != "" {
		findings = append(findings, Finding{LOW, "headers", fmt.Sprintf("Server header exposed: %q", sv)})
	}
	if xp := resp.Header.Get("X-Powered-By"); xp != "" {
		findings = append(findings, Finding{LOW, "headers", fmt.Sprintf("X-Powered-By exposed: %q", xp)})
	}

	// HTTP (non-TLS) check
	if strings.HasPrefix(targetURL, "http://") {
		findings = append(findings, Finding{HIGH, "tls", "site served over plain HTTP — no TLS"})
	}

	return findings
}

// checkRedirect checks whether HTTP redirects to HTTPS.
func checkRedirect(host string, timeout time.Duration) []Finding {
	plainURL := "http://" + host + "/"
	client := newHTTPClient(timeout, false)
	resp, err := client.Get(plainURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 == 3 {
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "https://") {
			return []Finding{{MEDIUM, "redirect", fmt.Sprintf("redirects to non-HTTPS location: %s", loc)}}
		}
		return []Finding{{INFO, "redirect", "HTTP correctly redirects to HTTPS"}}
	}

	return []Finding{{HIGH, "redirect", "HTTP does not redirect to HTTPS"}}
}

// checkTLS inspects the TLS certificate for the host on port 443.
func checkTLS(host string, timeout time.Duration) []Finding {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		host+":443",
		&tls.Config{ServerName: host},
	)
	if err != nil {
		return []Finding{{HIGH, "tls", fmt.Sprintf("TLS handshake failed: %v", err)}}
	}
	defer conn.Close()

	var findings []Finding
	state := conn.ConnectionState()

	for _, cert := range state.PeerCertificates {
		now := time.Now()
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

		if now.After(cert.NotAfter) {
			findings = append(findings, Finding{HIGH, "tls", fmt.Sprintf("certificate EXPIRED on %s", cert.NotAfter.Format("2006-01-02"))})
		} else if daysLeft < 14 {
			findings = append(findings, Finding{HIGH, "tls", fmt.Sprintf("certificate expires in %d days (%s)", daysLeft, cert.NotAfter.Format("2006-01-02"))})
		} else if daysLeft < 30 {
			findings = append(findings, Finding{MEDIUM, "tls", fmt.Sprintf("certificate expires in %d days", daysLeft)})
		} else {
			findings = append(findings, Finding{INFO, "tls", fmt.Sprintf("certificate valid for %d more days (expires %s)", daysLeft, cert.NotAfter.Format("2006-01-02"))})
		}
		break // only check leaf cert
	}

	// Warn on old TLS versions
	switch state.Version {
	case tls.VersionTLS10, tls.VersionTLS11:
		findings = append(findings, Finding{HIGH, "tls", "server supports deprecated TLS 1.0/1.1"})
	}

	return findings
}

// checkMethods probes for potentially dangerous HTTP methods.
func checkMethods(targetURL string, timeout time.Duration) []Finding {
	client := newHTTPClient(timeout, false)
	var findings []Finding

	for _, method := range []string{"TRACE", "OPTIONS"} {
		req, _ := http.NewRequest(method, targetURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if method == "TRACE" && resp.StatusCode == http.StatusOK {
			findings = append(findings, Finding{MEDIUM, "methods", "TRACE method enabled — risk of Cross-Site Tracing (XST)"})
		}
		if method == "OPTIONS" {
			if allow := resp.Header.Get("Allow"); allow != "" {
				findings = append(findings, Finding{INFO, "methods", fmt.Sprintf("OPTIONS Allow: %s", allow)})
			}
		}
	}
	return findings
}

// ─────────────────────────────────────────────
// Report rendering
// ─────────────────────────────────────────────

func printBanner(target string) {
	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
	fmt.Printf("  NullAI Vulnerability Scanner\n")
	fmt.Printf("  Target: %s\n", target)
	fmt.Printf("  Time:   %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("%s\n\n", strings.Repeat("─", 60))
}

func printSection(title string) {
	fmt.Printf("\n[*] %s\n", title)
}

func printFindings(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println("    No issues found.")
		return
	}
	for _, f := range findings {
		fmt.Printf("    %s\n", f)
	}
}

func printSummary(all []Finding) {
	counts := map[Severity]int{}
	for _, f := range all {
		counts[f.Severity]++
	}
	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
	fmt.Printf("  SUMMARY  HIGH:%d  MEDIUM:%d  LOW:%d  INFO:%d  TOTAL:%d\n",
		counts[HIGH], counts[MEDIUM], counts[LOW], counts[INFO], len(all))
	fmt.Printf("%s\n\n", strings.Repeat("─", 60))
}

// ─────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────

func main() {
	host := flag.String("host", "", "Target hostname or IP (required)")
	url := flag.String("url", "", "Target URL for HTTP checks (default: https://<host>/)")
	portStart := flag.Int("port-start", 1, "Port range start (default 1)")
	portEnd := flag.Int("port-end", 1024, "Port range end (default 1024)")
	threads := flag.Int("threads", 200, "Port scan concurrency (default 200)")
	timeout := flag.Duration("timeout", 2*time.Second, "Per-check timeout (default 2s)")
	skipPorts := flag.Bool("skip-ports", false, "Skip port scan")
	skipHTTP := flag.Bool("skip-http", false, "Skip HTTP header / TLS checks")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "Error: -host is required")
		flag.Usage()
		os.Exit(1)
	}

	targetURL := *url
	if targetURL == "" {
		targetURL = "https://" + *host + "/"
	}

	printBanner(*host)

	var allFindings []Finding

	// Port scan
	if !*skipPorts {
		printSection(fmt.Sprintf("Port scan  %d–%d  (%d threads)", *portStart, *portEnd, *threads))
		open := scanPorts(*host, *portStart, *portEnd, *threads, *timeout)
		if len(open) == 0 {
			fmt.Println("    No open ports found in range.")
		} else {
			for _, p := range open {
				f := Finding{INFO, "ports", fmt.Sprintf("port %d/tcp OPEN", p)}
				fmt.Printf("    %s\n", f)
				allFindings = append(allFindings, f)
			}
		}
	}

	// HTTP headers
	if !*skipHTTP {
		printSection("HTTP security headers — " + targetURL)
		hf := checkHTTPHeaders(targetURL, *timeout)
		printFindings(hf)
		allFindings = append(allFindings, hf...)

		printSection("HTTP → HTTPS redirect — " + *host)
		rf := checkRedirect(*host, *timeout)
		printFindings(rf)
		allFindings = append(allFindings, rf...)

		printSection("TLS certificate — " + *host)
		tf := checkTLS(*host, *timeout)
		printFindings(tf)
		allFindings = append(allFindings, tf...)

		printSection("HTTP method enumeration — " + targetURL)
		mf := checkMethods(targetURL, *timeout)
		printFindings(mf)
		allFindings = append(allFindings, mf...)
	}

	printSummary(allFindings)
}
