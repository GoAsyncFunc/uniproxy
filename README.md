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
	"log"
	"github.com/GoAsyncFunc/uniproxy/pkg"
)

func main() {
	client := pkg.New(&pkg.Config{
		APIHost:  "https://api.example.com",
		Key:      "your-node-token",
		NodeID:   1,
		NodeType: "hysteria2", // vmess, vless, trojan, etc.
		Timeout:  10,
	})

	// Use client...
}
```

### 2. Fetch Node Config

```go
config, err := client.GetNodeInfo()
if err != nil {
	log.Fatal(err)
}
if config != nil {
	log.Printf("Node config: %+v", config)
} else {
	log.Println("Config unmodified (304)")
}
```

### 3. Sync Users

```go
users, err := client.GetUserList()
if err != nil {
	log.Fatal(err)
}
log.Printf("Synced %d users", len(users))
```

### 4. Report Traffic

```go
err := client.ReportUserTraffic([]pkg.UserTraffic{
	{UID: 1, Upload: 1024, Download: 2048},
})
if err != nil {
	log.Printf("Report failed: %v", err)
}
```

## License

MIT License
