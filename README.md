# uniproxy

A lightweight, robust Go client for the UniProxy API.

## Features

- **Node Configuration**: Fetch configurations for VMess, VLESS, Trojan, Shadowsocks, Hysteria, Hysteria2, Tuic, AnyTLS, and more.
- **User Synchronization**: Efficiently retrieve and manage user lists.
- **Traffic Reporting**: Reliable user traffic usage reporting.
- **Health Checks**: Report node online status.
- **Resilient**: Built-in error handling and retry mechanisms.

## Installation

```bash
go get github.com/GoAsyncFunc/uniproxy
```

## Usage

### 1. Initialization

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
		NodeType: "hysteria2", // vmess, vless, trojan, etc.
		Timeout:  10,
		AuthMode: pkg.AuthModeHeaderOnly, // recommended when the panel supports bearer auth
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = ctx
	_ = client
}
```

`pkg.New` remains available for compatibility when the configuration has already been validated, but `pkg.NewWithError` is recommended for new code.

Configuration validation requires `APIHost` to use `http` or `https` with a host, rejects URL userinfo/query/fragment/path components, requires `Key`, requires `NodeID > 0`, and accepts these node types: `vmess`, `vless`, `shadowsocks`, `trojan`, `tuic`, `hysteria`, `hysteria2`, and `anytls`. The legacy `v2ray` node type is accepted as a compatibility alias for `vmess`.

`APIHost` should come from trusted configuration, not direct user input. Remote HTTP hosts are rejected by default; `http://localhost` and loopback IPs are allowed for local development. This validation is transport hardening, not complete SSRF protection; applications that accept user-controlled hosts must enforce their own hostname/IP allowlist. Prefer HTTPS in production because v1 retains query-token compatibility.

By default, v1 sends the node token in both places: the legacy `token` query parameter required by existing UniProxy panels and an `Authorization: Bearer <token>` header for deployments that can read header-based auth. Set `AuthModeHeaderOnly` for new deployments whose panels support bearer auth; use `AuthModeQueryOnly` only for legacy panels. Query-token modes can expose credentials through infrastructure URL logs, so prefer HTTPS and header-only auth when possible.

The deprecated public `Client.APIHost`, `Client.APISendIP`, `Client.Token`, `Client.NodeType`, and `Client.NodeId` fields are informational compatibility fields; mutating them does not change request behavior. `Config.Debug` and `Client.Debug(true)` are disabled/deprecated because request debugging can expose credentials. Use sanitized application-level logging instead.

Avoid logging full `Config`, `Client`, or `NodeInfo` values because they can include tokens, private keys, or server keys. Common `Client`, `APIError`, and sensitive model formatters redact known sensitive fields, but callers should still avoid logging full remote panel payloads.

Public methods validate caller and panel data before sending or returning it: `ReportUserTraffic` rejects non-positive or duplicate UIDs and negative counters; `ReportNodeOnlineUsers` rejects nil data, non-positive UIDs, empty user lists, and malformed `IP_suffix` entries; `GetAliveList` rejects malformed alive responses. Caller-input validation errors may be plain errors rather than `APIError`.

### 2. Fetch Node Config

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

### 3. Sync Users

```go
users, err := client.GetUserList(ctx)
if err != nil {
	log.Fatal(err)
}
log.Printf("Synced %d users", len(users))

cachedUsers := client.CachedUserList() // returns a copy
log.Printf("Cached %d users", len(cachedUsers))
```

`GetUserList` returns a copy of cached users, so callers can mutate the returned slice without changing the client's internal cache.

### 4. Report Traffic

```go
err := client.ReportUserTraffic(ctx, []pkg.UserTraffic{
	{UID: 1, Upload: 1024, Download: 2048},
})
if err != nil {
	log.Printf("Report failed: %v", err)
}
```

### 5. Report Online Users and Fetch Alive Counts

```go
err := client.ReportNodeOnlineUsers(ctx, map[int][]string{
	1: {"203.0.113.1_1", "203.0.113.2_1"},
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

## License

MIT License
