# uniproxy

A lightweight, robust Go client for the UniProxy API.

## Features

- **Node configuration**: VMess, VLESS, Trojan, Shadowsocks, Hysteria, Hysteria2, Tuic, AnyTLS.
- **User sync**: Retrieve and cache user lists with ETag-based 304 handling.
- **Traffic reporting**: Report user upload/download counters.
- **Online tracking**: Report online users and fetch alive counts.
- **Resilient**: Sanitized errors, GET-only retry, response-size limits.

## Installation

```bash
go get github.com/GoAsyncFunc/uniproxy
```

## Usage

### Initialization

```go
package main

import (
	"context"
	"log"

	"github.com/GoAsyncFunc/uniproxy/pkg"
)

func main() {
	ctx := context.Background()

	client, err := pkg.NewWithError(&pkg.Config{
		APIHost:  "https://api.example.com",
		Key:      "your-node-token",
		NodeID:   1,
		NodeType: "hysteria2", // vmess, vless, trojan, shadowsocks, tuic, hysteria, hysteria2, anytls
		Timeout:  10,
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = ctx
	_ = client
}
```

`pkg.New` is retained for compatibility but logs a warning and returns `nil`
on invalid config. Prefer `pkg.NewWithError` in new code.

### Config validation

`validateConfig` requires:

- `APIHost`: `http`/`https` scheme with a host, no userinfo/path/query/fragment.
  Plain `http` is rejected unless the host is `localhost` or a loopback IP.
- `Key`: non-empty.
- `NodeID`: positive.
- `NodeType`: one of `vmess`, `vless`, `shadowsocks`, `trojan`, `tuic`,
  `hysteria`, `hysteria2`, `anytls`. The legacy `v2ray` value is normalized
  to `vmess`.
- `APISendIP` (optional): valid IPv4/IPv6.
- `Timeout`: seconds; zero/negative values retain the 5-second default.
  Positive values that overflow `time.Duration` are rejected.

The host check is transport hardening, not full SSRF protection. Applications
that accept user-controlled hosts must enforce their own allowlist.

### Connections and lifecycle

The client uses Go's native dual-stack dialing (Happy Eyeballs), rather than
waiting for an IPv4-only attempt to fail before trying IPv6. `APISendIP`, when
set, binds outgoing connections to that local address and therefore constrains
the usable address family. The standard transport's proxy and TLS behavior is
preserved.

Call `client.CloseIdleConnections()` when retiring a client to release pooled
idle connections. It does not interrupt active requests, clear caches, or make
the client unusable; later requests can open new connections. Cancel the request
contexts separately if active requests also need to stop.

### Authentication

The node token is sent as the `token=` query parameter on every request, which
matches existing UniProxy panels. URLs can appear in proxy/CDN access logs, so
**always use HTTPS in production**.

### Logging and debugging

- Treat `Config`, `Client`, and `NodeInfo` as secret — they contain tokens,
  private keys, or server keys. The library's `Stringer`/`GoStringer`
  implementations on `Client`, `APIError`, and sensitive models redact known
  fields, but full panel payloads should not be logged.
- `Config.Debug` and `Client.Debug(true)` are no-ops that emit a warning;
  request-level debug logging is disabled because it can leak credentials.
- The deprecated public fields `Client.APIHost`, `Client.APISendIP`,
  `Client.Token`, `Client.NodeType`, and `Client.NodeId` are informational.
  Mutating them does not change request behavior.

### Production checklist

- Use HTTPS for `APIHost`.
- Treat `APIHost` as operator-controlled config; allowlist hosts when user
  input can influence them.
- Log `APIError.Error()` (which redacts URLs and bodies) instead of raw
  `APIError` fields, full `Config`, full `Client`, or full panel payloads.
- Keep `Config.Debug` disabled in production.

### Fetch node config

```go
config, err := client.GetNodeInfo(ctx)
if err != nil {
	log.Fatal(err)
}
if config != nil {
	log.Printf("Node type=%s port=%d routes=%d", config.Type, config.Common.ServerPort, len(config.Routes))
} else {
	log.Println("Config unmodified (304)")
}
```

`GetNodeInfo` returns `(nil, nil)` on a valid `304 Not Modified`.
For both node and user requests, a 304 requires a previously validated response
and a non-empty ETag sent with the request; otherwise it is a parse error.
A 304 may update the existing ETag. An accepted full response without an ETag
clears the old validator, even if its body is unchanged. Invalid full responses
leave the cached data, body hash, and ETag untouched.

Node push/pull intervals default to 60 seconds when `base_config` or an individual
interval is missing/null. Explicit intervals must convert to positive seconds
without overflowing `time.Duration`; invalid values reject the entire node
response. Integer strings are supported and fractional numbers are truncated
for compatibility (e.g. 2.5 becomes 2 seconds; 0.5 is rejected).
The public `IntervalToTime` helper still returns 0 for invalid/non-positive or
overflowing input; callers using it directly must check before creating timers.
VLESS/VMess `tls_settings.xver` accepts integers or integer strings from 0 to 2;
missing/null values default to 0. Hysteria configs must explicitly report
`version: 1` for `hysteria` or `version: 2` for `hysteria2`. Missing or mismatched
versions are parse errors and do not update cache validators.

### Sync users

```go
users, err := client.GetUserList(ctx)
if err != nil {
	log.Fatal(err)
}
log.Printf("Synced %d users", len(users))

cached := client.CachedUserList()
log.Printf("Cached %d users", len(cached))
```

`GetUserList` returns a fresh copy on 200 and a cached copy on 304. Both
`GetUserList` and `CachedUserList` return copies, so mutating the slice does
not affect internal state.

A 200 response must contain a `users` array. `{"users":[]}` is a valid empty
list; missing/null `users` or invalid entries return a parse error without
changing the cached users, body hash, or ETag. Waiting for another node/user
refresh respects the caller's context cancellation and deadline.

### Report traffic

```go
err := client.ReportUserTraffic(ctx, []pkg.UserTraffic{
	{UID: 1, Upload: 1024, Download: 2048},
})
if err != nil {
	log.Printf("Report failed: %v", err)
}
```

`ReportUserTraffic` rejects non-positive UIDs, duplicate UIDs, and negative
counters. Empty input is a no-op.

Counters are **incremental bytes since the previous reporting snapshot**, not
lifetime totals: `Upload` is user upload (client to proxy), and `Download` is
user download (proxy to client). Do not apply the panel's traffic multiplier
locally; the panel applies its configured rate. A timeout or lost response can
mean the report was accepted, so do not blindly replay a failed report. The
current protocol has no report ID or exactly-once guarantee.

### Report online users and fetch alive counts

```go
err := client.ReportNodeOnlineUsers(ctx, map[int][]netip.Addr{
	1: {netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
})
if err != nil {
	log.Printf("Online report failed: %v", err)
}

alive, err := client.GetAliveList(ctx)
if err != nil {
	log.Printf("Alive list fetch failed: %v", err)
}
log.Printf("Alive counts: %+v", alive)
```

`ReportNodeOnlineUsers`:

- Empty/nil input is a no-op. Newer v2board panels accept empty alive reports;
  skipping them also preserves compatibility with older panels that may return
  500 on empty payloads with strict cache drivers.
- Rejects non-positive UIDs, invalid addresses, and IPv6 addresses with zones.
- A positive UID with an empty/nil IP slice sends `{"uid":[]}` to clear that
  user's online state on this node. Omitting a UID does not clear its state.
- IPv4-mapped IPv6 is normalized to IPv4; addresses are deduplicated per UID.
- Each normalized IP is tagged as `<ip>_<NodeID>` before posting.

To report a user going offline:

```go
err := client.ReportNodeOnlineUsers(ctx, map[int][]netip.Addr{1: {}})
```

Callers must track transitions themselves; this client does not retain online
snapshots. The referenced panel supports per-user empty lists, but other panel
versions should be verified before relying on explicit clearing. Online counts
are eventually consistent: the panel caches `alivelist` for 60 seconds and uses
expiry-based cleanup for omitted users.

`GetAliveList` requires a non-null `alive` object (`{"alive":{}}` is valid).
Missing/null objects, non-positive UIDs, null counts, and negative counts are
parse errors, not successful empty lists.

### Errors and retries

- Only GET requests are retried internally, at most twice, for HTTP
  500/502/503/504 and transient network failures. Exponential backoff with
  jitter waits 100–200ms before the first retry and 200–400ms before the second.
  Response-size violations, canceled contexts, permanent DNS failures, and
  certificate validation failures are not retried.
  `ReportUserTraffic` and `ReportNodeOnlineUsers` are not retried by the
  client.
- Redirects are not followed; configure `APIHost` with the final API origin.
  Reports require a successful HTTP status and a JSON `{"data":true}`
  acknowledgement. HTTP 204 remains accepted for compatibility. Empty HTTP
  200 responses, HTML pages, and missing/false acknowledgements are errors.
- Error messages longer than 8 KiB are replaced with a fixed summary before
  redaction, including wrapped errors. Oversized response bodies are still
  rejected at the 8 MiB transport limit.
- All API errors are `*pkg.APIError`. See [docs/error_handling.md](docs/error_handling.md)
  for classification, sentinel matching, and logging guidance.
- Caller-input validation errors (bad UIDs, invalid IPs, etc.) may be plain
  `error` values, not `*APIError`.

### Panel compatibility

The response contracts are checked against
[GoAsyncFunc/v2board at `99f8526`](https://github.com/GoAsyncFunc/v2board/blob/99f8526eddb72a4e8f6cbccd58cc0656bb91fe88/app/Http/Controllers/V1/Server/UniProxyController.php).
That implementation returns user arrays, quoted ETags, JSON report
acknowledgements, and an object for `alive` counts. It uses HTTP 500 even for
invalid tokens or missing nodes, so repeated 500 responses may require a
configuration fix rather than further retries. It accepts empty online
reports; this client continues skipping them for older-panel compatibility.

Traffic handling dispatches asynchronous jobs in
[UserService::trafficFetch](https://github.com/GoAsyncFunc/v2board/blob/99f8526eddb72a4e8f6cbccd58cc0656bb91fe88/app/Services/UserService.php).
An acknowledgement confirms submission, not completion of those jobs. A lost
response does not prove the report was rejected; blindly repeating traffic
reports can duplicate accounting.

## License

MIT License
