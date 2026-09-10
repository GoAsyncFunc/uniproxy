package pkg

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestIntegrationPanelFetch never runs without explicit opt-in. It intentionally
// does not create records or call POST endpoints. GETs can update panel caches.
func TestIntegrationPanelFetch(t *testing.T) {
	if os.Getenv("UNIPROXY_INTEGRATION") != "1" {
		t.Skip("explicit integration opt-in required")
	}
	path := os.Getenv("UNIPROXY_INTEGRATION_CONFIG")
	if path == "" {
		t.Fatal("set UNIPROXY_INTEGRATION_CONFIG to a private local JSON file")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("integration config must be a readable regular file")
	}
	if info.Size() > 64*1024 {
		t.Fatal("integration config exceeds 64 KiB")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatal("integration config must not be group/world accessible (use chmod 600)")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("cannot open integration config")
	}
	defer func() { _ = file.Close() }()
	// Deliberately exclude Debug, Observer and arbitrary client options.
	var config struct {
		APIHost, Key, NodeType string
		NodeID                 int
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		t.Fatal("invalid integration config (details suppressed)")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("integration config must contain exactly one JSON object")
	}
	client, err := NewWithError(&Config{APIHost: config.APIHost, Key: config.Key, NodeType: config.NodeType, NodeID: config.NodeID, Timeout: 10})
	if err != nil {
		t.Fatal("invalid integration client configuration (details suppressed)")
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	node, err := client.GetNodeInfo(ctx)
	if err != nil || node == nil {
		t.Fatal("initial config fetch failed (details suppressed)")
	}
	// Do not assume 304: operators may legitimately change configs during a run.
	if _, err := client.GetNodeInfo(ctx); err != nil {
		t.Fatal("repeat config fetch failed (details suppressed)")
	}
	if _, err := client.GetUserList(ctx); err != nil {
		t.Fatal("initial user fetch failed (details suppressed)")
	}
	if _, err := client.GetUserList(ctx); err != nil {
		t.Fatal("repeat user fetch failed (details suppressed)")
	}
	if _, err := client.GetAliveList(ctx); err != nil {
		t.Fatal("alive-list fetch failed (details suppressed)")
	}
	t.Log("config, users and alive-list fetch contracts passed; no POSTs sent")
}
