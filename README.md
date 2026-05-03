# Vulnerability Scanner

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> **Difficulty:** Beginner | **Language:** Go | **No external dependencies**

Non-intrusive vulnerability scanner written in Go. Checks a target host for open ports, missing HTTP security headers, plain-HTTP usage, TLS certificate validity, deprecated TLS versions, and dangerous HTTP methods. Findings are severity-rated (HIGH / MEDIUM / LOW / INFO) with a summary at the end. Zero third-party dependencies — pure standard library.

---

## Project Structure

```
05-simple-vuln-scanner/
├── README.md
├── .gitignore
├── src/
│   ├── scanner.go        ← All checks + CLI entry point
│   ├── scanner_test.go   ← Go test suite
│   └── go.mod
└── docs/
    └── NOTES.md
```

---

## Build

```bash
cd src
go build -o vuln-scanner .
```

Or run directly:

```bash
go run scanner.go -host example.com
```

---

## Usage

```bash
# Full scan (ports 1–1024 + HTTP checks)
./vuln-scanner -host example.com

# Scan only HTTP/TLS checks (skip port scan)
./vuln-scanner -host example.com -skip-ports

# Scan full port range with more threads
./vuln-scanner -host 192.168.1.1 -port-start 1 -port-end 65535 -threads 500

# Custom target URL (useful when port differs from 443)
./vuln-scanner -host example.com -url https://example.com:8443/

# Adjust timeout
./vuln-scanner -host slow-host.internal -timeout 5s
```

**Example output:**
```
────────────────────────────────────────────────────────────
  NullAI Vulnerability Scanner
  Target: example.com
  Time:   2026-04-28 14:02:11
────────────────────────────────────────────────────────────

[*] Port scan  1–1024  (200 threads)
    [INFO] ports      port 80/tcp OPEN
    [INFO] ports      port 443/tcp OPEN

[*] HTTP security headers — https://example.com/
    [HIGH  ] headers   missing Strict-Transport-Security
    [MEDIUM] headers   missing Content-Security-Policy
    [LOW   ] headers   Server header exposed: "ECS (dcb/7EC7)"

[*] TLS certificate — example.com
    [INFO  ] tls       certificate valid for 182 more days (expires 2026-10-24)

────────────────────────────────────────────────────────────
  SUMMARY  HIGH:1  MEDIUM:1  LOW:1  INFO:3  TOTAL:6
────────────────────────────────────────────────────────────
```

---

## Run Tests

```bash
cd src
go test -v ./...
```

---

## Checks

| Check | What It Tests | Severity |
|-------|-------------|---------|
| Port scan | Open TCP ports in range | INFO |
| HSTS | `Strict-Transport-Security` header present | HIGH if missing |
| CSP | `Content-Security-Policy` header | MEDIUM if missing |
| X-Content-Type-Options | Header present | MEDIUM if missing |
| X-Frame-Options | Header present | MEDIUM if missing |
| Server/X-Powered-By | Banner disclosure | LOW |
| Plain HTTP | Site served without TLS | HIGH |
| HTTP redirect | HTTP → HTTPS redirect in place | HIGH if missing |
| TLS cert expiry | Days until certificate expires | HIGH/MEDIUM/INFO |
| TLS version | Deprecated TLS 1.0/1.1 | HIGH |
| TRACE method | HTTP TRACE enabled (XST risk) | MEDIUM |
| OPTIONS method | Allowed methods enumeration | INFO |

---

---

## Challenges & Extensions

- Add **subdomain discovery** by resolving a wordlist against the target domain
- Parse **HTML source** to find version strings in meta tags and JS comments
- Add a **JSON/CSV report** output mode
- Add **rate limiting** to avoid overwhelming targets
- Query the **NVD API** to match detected software versions against CVEs
- Implement **CORS misconfiguration detection** (reflect Origin header check)

---

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [RFC 7230 — HTTP/1.1](https://tools.ietf.org/html/rfc7230)
- MITRE ATT&CK: [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)

---

