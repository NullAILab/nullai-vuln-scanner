# Architecture Notes — Simple Vulnerability Scanner

## Design philosophy

This is a non-intrusive, passive scanner. It:
- Uses only standard TCP connect (no SYN/raw-socket) for port scanning
- Sends only GET, OPTIONS, TRACE — no exploit payloads
- Does not modify any remote state
- Can be run against your own servers as a quick posture check

## Port scan: worker pool over channel

Same pattern as the C++ port scanner (project 01), but idiomatic Go:
- A buffered channel holds all ports as work items
- N goroutines drain the channel concurrently
- A mutex guards the shared `open []int` slice
- `sort.Ints` at the end normalises output regardless of goroutine scheduling

The channel pattern is cleaner than a mutex-guarded queue because the channel
itself provides backpressure and clean goroutine termination (range over closed channel).

## HTTP client configuration

A custom `http.Transport` is created for each check function so:
- Redirect following can be toggled per check (checkRedirect needs one hop)
- TLS verification is always enabled (we want to catch cert failures)
- Timeouts are consistent across all checks

`InsecureSkipVerify: false` is explicit — the linter annotation `//nolint:gosec`
silences the false positive that fires on any `tls.Config` struct literal.

## TLS check

`tls.DialWithDialer` gives us the raw `*tls.Conn` so we can inspect:
- `ConnectionState().PeerCertificates[0].NotAfter` → days until expiry
- `ConnectionState().Version` → detect deprecated TLS 1.0/1.1

Only the leaf certificate is checked. Intermediate and root certs are not
inspected — that is out of scope for this introductory project.

## Severity mapping

| Severity | Meaning |
|----------|---------|
| HIGH     | Immediate risk: plain HTTP, HSTS missing, expired cert, TRACE enabled |
| MEDIUM   | Should fix soon: missing CSP/XFO, no HTTP→HTTPS redirect |
| LOW      | Information disclosure: Server/X-Powered-By banners |
| INFO     | Neutral observation: open ports, OPTIONS methods, valid cert |
