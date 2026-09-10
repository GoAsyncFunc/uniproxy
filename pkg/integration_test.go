package pkg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	resty "github.com/go-resty/resty/v2"
)

const integrationConfigLimit = 64 * 1024

var errIntegrationDisabled = errors.New("explicit integration opt-in required")

type integrationConfig struct {
	APIHost, Key, NodeType string
	NodeID                 int
}

func decodeIntegrationConfig(reader io.Reader) (integrationConfig, error) {
	var config integrationConfig
	body, err := io.ReadAll(io.LimitReader(reader, integrationConfigLimit+1))
	if err != nil {
		return config, errors.New("cannot read integration config")
	}
	if len(body) > integrationConfigLimit {
		return config, errors.New("integration config exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return integrationConfig{}, errors.New("invalid integration config (details suppressed)")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return integrationConfig{}, errors.New("integration config must contain exactly one JSON object")
	}
	return config, nil
}

func readIntegrationConfig(path string) (integrationConfig, error) {
	var empty integrationConfig
	if path == "" {
		return empty, errors.New("set UNIPROXY_INTEGRATION_CONFIG to a private local JSON file")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return empty, errors.New("integration config must be a readable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return empty, errors.New("cannot open integration config")
	}
	defer func() { _ = file.Close() }()
	// Check the opened file too, rather than relying solely on pre-open metadata.
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return empty, errors.New("integration config must be a readable regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return empty, errors.New("integration config must not be group/world accessible (use chmod 600)")
	}
	if info.Size() > integrationConfigLimit {
		return empty, errors.New("integration config exceeds 64 KiB")
	}
	return decodeIntegrationConfig(file)
}

func runIntegrationPanelFetch(ctx context.Context, enabled, path string) error {
	if enabled != "1" {
		return errIntegrationDisabled
	}
	config, err := readIntegrationConfig(path)
	if err != nil {
		return err
	}
	client, err := NewWithError(&Config{APIHost: config.APIHost, Key: config.Key, NodeType: config.NodeType, NodeID: config.NodeID, Timeout: 10})
	if err != nil {
		return errors.New("invalid integration client configuration (details suppressed)")
	}
	defer client.CloseIdleConnections()
	// Test runner errors are fixed summaries; do not emit underlying transport
	// diagnostics or panel bodies through library callbacks either.
	client.client.OnError(func(*resty.Request, error) {})
	node, err := client.GetNodeInfo(ctx)
	if err != nil || node == nil {
		return errors.New("initial config fetch failed (details suppressed)")
	}
	if _, err := client.GetNodeInfo(ctx); err != nil {
		return errors.New("repeat config fetch failed (details suppressed)")
	}
	if _, err := client.GetUserList(ctx); err != nil {
		return errors.New("initial user fetch failed (details suppressed)")
	}
	if _, err := client.GetUserList(ctx); err != nil {
		return errors.New("repeat user fetch failed (details suppressed)")
	}
	if _, err := client.GetAliveList(ctx); err != nil {
		return errors.New("alive-list fetch failed (details suppressed)")
	}
	return nil
}

// GETs can update panel caches. No records are created and no POSTs are sent.
func TestIntegrationPanelFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	err := runIntegrationPanelFetch(ctx, os.Getenv("UNIPROXY_INTEGRATION"), os.Getenv("UNIPROXY_INTEGRATION_CONFIG"))
	if errors.Is(err, errIntegrationDisabled) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Log("config, users and alive-list fetch contracts passed; no POSTs sent")
}
