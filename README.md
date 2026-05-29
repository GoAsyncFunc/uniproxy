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

The host check is transport hardening, not full SSRF protection. Applications
that accept user-controlled hosts must enforce their own allowlist.

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

`GetNodeInfo` returns `(nil, nil)` on `304 Not Modified`.

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
- Rejects non-positive UIDs, empty IP lists, and invalid `netip.Addr` values.
- Each IP is tagged as `<ip>_<NodeID>` before posting.

`GetAliveList` rejects malformed alive responses (non-positive UIDs, negative
counts) as parse errors.

### Errors and retries

- Only GET requests are retried internally (2 retries, 10ms backoff).
  `ReportUserTraffic` and `ReportNodeOnlineUsers` are not retried by the
  client.
- All API errors are `*pkg.APIError`. See [docs/error_handling.md](docs/error_handling.md)
  for classification, sentinel matching, and logging guidance.
- Caller-input validation errors (bad UIDs, invalid IPs, etc.) may be plain
  `error` values, not `*APIError`.

## License

MIT License
