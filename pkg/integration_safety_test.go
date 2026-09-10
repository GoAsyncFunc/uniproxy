package pkg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func privateIntegrationFile(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "panel.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func integrationFixtureFile(t *testing.T, host string) string {
	t.Helper()
	body, err := json.Marshal(integrationConfig{APIHost: host, Key: "fixture-secret", NodeType: Vless, NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	return privateIntegrationFile(t, body)
}

func TestIntegrationDisabledBeforeConfigAccess(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	path := integrationFixtureFile(t, server.URL)
	for _, enabled := range []string{"", "0", "true", " 1"} {
		for _, file := range []string{path, "", filepath.Join(t.TempDir(), "does-not-exist"), t.TempDir()} {
			if err := runIntegrationPanelFetch(context.Background(), enabled, file); !errors.Is(err, errIntegrationDisabled) {
				t.Fatalf("disabled entry accessed config: %v", err)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("disabled integration made a request")
	}
}

type countingIntegrationReader struct{ count int }

func (r *countingIntegrationReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.count += len(p)
	return len(p), nil
}

type failingIntegrationReader struct{}

func (failingIntegrationReader) Read([]byte) (int, error) { return 0, errors.New("fixture-secret") }

func TestIntegrationConfigReadBound(t *testing.T) {
	reader := &countingIntegrationReader{}
	if _, err := decodeIntegrationConfig(reader); err == nil {
		t.Fatal("oversized stream accepted")
	}
	if reader.count != integrationConfigLimit+1 {
		t.Fatalf("read %d bytes", reader.count)
	}
	body := `{"APIHost":"http://localhost","Key":"fixture-secret","NodeType":"vless","NodeID":1}`
	if _, err := decodeIntegrationConfig(strings.NewReader(body + strings.Repeat(" ", integrationConfigLimit-len(body)))); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeIntegrationConfig(failingIntegrationReader{}); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("reader error not suppressed")
	}
}

func TestIntegrationInvalidConfigDoesNotLeakOrConnect(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	var logs bytes.Buffer
	original := log.StandardLogger().Out
	log.SetOutput(&logs)
	defer log.SetOutput(original)
	for _, body := range []string{`{"Key":"fixture-secret",`, `{"Key":"fixture-secret","Debug":true}`, `{"Key":"fixture-secret"} {}`, `null`, `[]`, strings.Repeat("fixture-secret", 6000)} {
		err := runIntegrationPanelFetch(context.Background(), "1", privateIntegrationFile(t, []byte(body)))
		if err == nil || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("unsafe config error")
		}
	}
	body, _ := json.Marshal(integrationConfig{APIHost: server.URL, Key: "fixture-secret", NodeType: "invalid", NodeID: 1})
	if err := runIntegrationPanelFetch(context.Background(), "1", privateIntegrationFile(t, body)); err == nil {
		t.Fatal("invalid client accepted")
	}
	if calls.Load() != 0 || strings.Contains(logs.String(), "fixture-secret") {
		t.Fatal("invalid config caused request or secret logging")
	}
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "fixture-secret")} {
		if _, err := readIntegrationConfig(path); err == nil || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("unsafe path error")
		}
	}
	if runtime.GOOS != "windows" {
		path := integrationFixtureFile(t, server.URL)
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readIntegrationConfig(path); err == nil {
			t.Fatal("world-readable config accepted")
		}
	}
}

func TestIntegrationOnlyExpectedGETsAndClosesIdle(t *testing.T) {
	closed := make(chan struct{}, 8)
	var calls atomic.Int32
	paths := []string{apiConfigPath, apiConfigPath, apiUserPath, apiUserPath, apiAliveListPath}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(calls.Add(1)) - 1
		if i >= len(paths) || r.Method != http.MethodGet || r.URL.Path != paths[i] {
			t.Error("unexpected request")
			w.WriteHeader(400)
			return
		}
		if r.URL.Query().Get("token") != "fixture-secret" {
			t.Error("missing fixture token")
		}
		w.Header().Set(headerETag, `"fixture"`)
		if i == 1 || i == 3 {
			w.WriteHeader(304)
			return
		}
		body := `{"alive":{}}`
		switch i {
		case 0:
			body = `{"server_port":443}`
		case 2:
			body = `{"users":[]}`
		}
		_, _ = io.WriteString(w, body)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()
	if err := runIntegrationPanelFetch(context.Background(), "1", integrationFixtureFile(t, server.URL)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 5 {
		t.Fatal("incorrect request count")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection not closed")
	}
}

func TestIntegrationFailureAndCancellation(t *testing.T) {
	for _, name := range []string{"response-error", "cancel", "deadline"} {
		t.Run(name, func(t *testing.T) {
			cancelRequest := name != "response-error"
			started := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				close(started)
				if cancelRequest {
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				w.WriteHeader(400)
				_, _ = io.WriteString(w, "fixture-secret")
			}))
			defer server.Close()
			defer close(release)
			var logs bytes.Buffer
			original := log.StandardLogger().Out
			log.SetOutput(&logs)
			defer log.SetOutput(original)
			var ctx context.Context
			var cancel context.CancelFunc
			if name == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			path := integrationFixtureFile(t, server.URL)
			done := make(chan error, 1)
			go func() { done <- runIntegrationPanelFetch(ctx, "1", path) }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request not started")
			}
			if name == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil || strings.Contains(err.Error(), "fixture-secret") {
					t.Fatal("unsafe request error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("request failed to finish")
			}
			if calls.Load() != 1 || strings.Contains(logs.String(), "fixture-secret") {
				t.Fatal("unexpected retry or secret logging")
			}
		})
	}
}
