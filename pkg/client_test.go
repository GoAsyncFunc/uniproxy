package pkg

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	resty "github.com/go-resty/resty/v2"
)

type captureRestyLogger struct {
	mu  sync.Mutex
	log strings.Builder
}

func (l *captureRestyLogger) Errorf(format string, v ...interface{}) {
	l.write(format, v...)
}

func (l *captureRestyLogger) Warnf(format string, v ...interface{}) {
	l.write(format, v...)
}

func (l *captureRestyLogger) Debugf(format string, v ...interface{}) {
	l.write(format, v...)
}

func (l *captureRestyLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.log.String()
}

func (l *captureRestyLogger) write(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(&l.log, format, v...)
}

func newTestClient(t *testing.T, apiHost, nodeType string) *Client {
	t.Helper()
	client := New(&Config{APIHost: apiHost, Key: "token", NodeID: 1, NodeType: nodeType, Timeout: 1})
	if client == nil {
		t.Fatal("client is nil")
	}
	return client
}

func TestNewWithError_ValidatesConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{name: "nil config", config: nil},
		{name: "empty host", config: &Config{Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "whitespace host", config: &Config{APIHost: "   ", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "invalid host", config: &Config{APIHost: "://bad", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "host without scheme", config: &Config{APIHost: "example.com", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "host without hostname", config: &Config{APIHost: "http://", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "unsupported scheme", config: &Config{APIHost: "ftp://example.com", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "host with username", config: &Config{APIHost: "https://token@example.com", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "host with username and password", config: &Config{APIHost: "https://user:pass@example.com", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "host with query", config: &Config{APIHost: "https://example.com?token=secret", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "host with fragment", config: &Config{APIHost: "https://example.com#secret", Key: "token", NodeID: 1, NodeType: "vless"}},
		{name: "empty key", config: &Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "vless"}},
		{name: "whitespace key", config: &Config{APIHost: "http://127.0.0.1", Key: "   ", NodeID: 1, NodeType: "vless"}},
		{name: "zero node id", config: &Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 0, NodeType: "vless"}},
		{name: "negative node id", config: &Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: -1, NodeType: "vless"}},
		{name: "unsupported node type", config: &Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: "unknown"}},
		{name: "invalid send ip", config: &Config{APIHost: "http://127.0.0.1", APISendIP: "not-an-ip", Key: "token", NodeID: 1, NodeType: "vless"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewWithError(tt.config)
			if err == nil {
				t.Fatalf("expected error, got client %#v", client)
			}
		})
	}
}

func TestNewWithError_ValidatesAPIHostAuthority(t *testing.T) {
	tests := []struct {
		name    string
		apiHost string
		wantErr bool
	}{
		{name: "https host", apiHost: "https://example.com"},
		{name: "https host trailing slash", apiHost: "https://example.com/"},
		{name: "https host with port", apiHost: "https://example.com:8443"},
		{name: "localhost http", apiHost: "http://localhost"},
		{name: "ipv4 loopback http", apiHost: "http://127.0.0.1"},
		{name: "ipv6 loopback http", apiHost: "http://[::1]"},
		{name: "empty hostname with port", apiHost: "https://:443", wantErr: true},
		{name: "invalid port", apiHost: "https://example.com:bad", wantErr: true},
		{name: "non root path", apiHost: "https://example.com/panel", wantErr: true},
		{name: "escaped non root path", apiHost: "https://example.com/%2fsecret", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewWithError(&Config{APIHost: tt.apiHost, Key: "token", NodeID: 1, NodeType: "vless"})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got client %#v", client)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client == nil {
				t.Fatal("client is nil")
			}
		})
	}
}

func TestNew_NilConfigDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New(nil) panicked: %v", r)
		}
	}()

	client := New(nil)
	if client != nil {
		t.Fatalf("New(nil) = %#v, want nil", client)
	}
}

func TestNewWithError_InvalidAPIHostDoesNotEchoSecrets(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name:   "invalid api host",
			config: &Config{APIHost: "https://example.com/%zz?token=secret-token", Key: "token", NodeID: 1, NodeType: "vless"},
		},
		{
			name:   "invalid api send ip",
			config: &Config{APIHost: "http://127.0.0.1", APISendIP: "203.0.113.1_secret-token", Key: "token", NodeID: 1, NodeType: "vless"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWithError(tt.config)
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("error leaked secret in %q", err.Error())
			}
		})
	}
}

func TestNewWithError_RejectsRemoteHTTP(t *testing.T) {
	client, err := NewWithError(&Config{APIHost: "http://example.com", Key: "token", NodeID: 1, NodeType: "vless"})
	if err == nil {
		t.Fatalf("expected remote http error, got client %#v", client)
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("error = %q, want https guidance", err.Error())
	}
}

func TestRedactedRestyClientFormatting(t *testing.T) {
	client := redactedRestyClient{Client: resty.New()}

	for name, value := range map[string]string{
		"String":   fmt.Sprint(client),
		"format":   fmt.Sprintf("%+v", client),
		"GoString": fmt.Sprintf("%#v", client),
	} {
		if value != "REDACTED" {
			t.Fatalf("%s = %q, want REDACTED", name, value)
		}
	}
}

func TestClientStringOutputRedactsToken(t *testing.T) {
	secret := "secret-token"
	client := New(&Config{APIHost: "https://example.com", Key: secret, NodeID: 1, NodeType: "vless"})
	if client == nil {
		t.Fatal("client is nil")
	}

	clientValue := reflect.ValueOf(client).Elem().Interface()
	valueOutputs := map[string]string{
		"value fields": fmt.Sprintf("%+v", clientValue),
		"value go":     fmt.Sprintf("%#v", clientValue),
	}
	for name, output := range valueOutputs {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(output, secret) {
				t.Fatal("formatted client leaked token")
			}
			if !strings.Contains(output, "REDACTED") {
				t.Fatalf("formatted client = %q, want redaction marker", output)
			}
		})
	}

	apiHostSecret := "api-host-secret"
	fragmentSecret := "fragment-secret"
	client.APIHost = "https://example.com?token=" + apiHostSecret + "#" + fragmentSecret
	pointerOutputs := map[string]string{
		"default": fmt.Sprint(client),
		"fields":  fmt.Sprintf("%+v", client),
		"go":      fmt.Sprintf("%#v", client),
	}
	for name, output := range pointerOutputs {
		t.Run(name, func(t *testing.T) {
			for _, leaked := range []string{secret, apiHostSecret, fragmentSecret} {
				if strings.Contains(output, leaked) {
					t.Fatal("formatted client leaked a secret")
				}
			}
			if !strings.Contains(output, "REDACTED") {
				t.Fatalf("formatted client = %q, want redaction marker", output)
			}
		})
	}
}

func TestNewWithError_AcceptsSupportedNodeTypes(t *testing.T) {
	types := []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "anytls", "v2ray", "VLESS"}
	for _, nodeType := range types {
		t.Run(nodeType, func(t *testing.T) {
			client, err := NewWithError(&Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: nodeType})
			if err != nil {
				t.Fatalf("NewWithError failed: %v", err)
			}
			if client == nil {
				t.Fatal("client is nil")
			}
			if nodeType == "v2ray" && client.NodeType != Vmess {
				t.Fatalf("NodeType = %q, want %q", client.NodeType, Vmess)
			}
			if nodeType == "VLESS" && client.NodeType != Vless {
				t.Fatalf("NodeType = %q, want %q", client.NodeType, Vless)
			}
		})
	}
}

func TestClient_Concurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case apiConfigPath:
			w.Header().Set("ETag", "123")
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case apiUserPath:
			w.Header().Set("ETag", "456")
			_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vmess",
		Timeout:  1,
	})

	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.GetNodeInfo(ctx)
			if err != nil {
				t.Errorf("GetNodeInfo failed: %v", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.GetUserList(ctx)
			if err != nil {
				t.Errorf("GetUserList failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestClient_DebugDoesNotLogToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"alive":{"1":1}}`))
	}))
	defer server.Close()

	logger := &captureRestyLogger{}
	client := New(&Config{APIHost: server.URL, Key: "secret-token", NodeID: 1, NodeType: "vless", Debug: true})
	client.client.SetLogger(logger)
	client.Debug(true)

	if _, err := client.GetAliveList(context.Background()); err != nil {
		t.Fatalf("GetAliveList failed: %v", err)
	}
	if got := logger.String(); strings.Contains(got, "secret-token") {
		t.Fatalf("debug logs leaked token: %q", got)
	}
}
