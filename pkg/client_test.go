package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
		case "/api/v1/server/UniProxy/config":
			w.Header().Set("ETag", "123")
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case "/api/v1/server/UniProxy/user":
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

func TestClient_CheckResponseNilResponseReturnsNetworkError(t *testing.T) {
	client := New(&Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: "vless"})

	err := client.checkResponse(nil, apiPushPath, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsNetworkError() {
		t.Fatalf("expected network APIError, got %T: %v", err, err)
	}
}

func TestClient_GetWithRetryTreatsNilContextAsBackgroundOnRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vmess")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GetNodeInfo with nil context panicked: %v", r)
		}
	}()

	var ctx context.Context
	_, err := client.GetNodeInfo(ctx)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_PublicMethodsTreatNilContextAsBackground(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case apiConfigPath:
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case apiUserPath:
			_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
		case apiPushPath, apiAlivePath:
			w.WriteHeader(http.StatusNoContent)
		case apiAliveListPath:
			_, _ = w.Write([]byte(`{"alive": {"1": 1}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vmess")
	var ctx context.Context

	if _, err := client.GetNodeInfo(ctx); err != nil {
		t.Fatalf("GetNodeInfo with nil context failed: %v", err)
	}
	if _, err := client.GetUserList(ctx); err != nil {
		t.Fatalf("GetUserList with nil context failed: %v", err)
	}
	if err := client.ReportUserTraffic(ctx, []UserTraffic{{UID: 1, Upload: 1, Download: 1}}); err != nil {
		t.Fatalf("ReportUserTraffic with nil context failed: %v", err)
	}
	if err := client.ReportNodeOnlineUsers(ctx, map[int][]string{1: {"203.0.113.1_1"}}); err != nil {
		t.Fatalf("ReportNodeOnlineUsers with nil context failed: %v", err)
	}
	alive, err := client.GetAliveList(ctx)
	if err != nil {
		t.Fatalf("GetAliveList with nil context failed: %v", err)
	}
	if alive[1] != 1 {
		t.Fatalf("alive[1] = %d, want 1", alive[1])
	}
}

func TestClient_ReturnsAPIError_OnServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message": "internal error"}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	ctx := context.Background()

	_, err := client.GetNodeInfo(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", apiErr.StatusCode)
	}
	if !apiErr.IsServerError() {
		t.Error("expected IsServerError() to be true")
	}

	_, err = client.GetUserList(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", apiErr.StatusCode)
	}
}

func TestClient_ReturnsAPIError_OnParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "new-etag")
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	ctx := context.Background()

	_, err := client.GetNodeInfo(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsParseError() {
		t.Errorf("expected ParseError, got type %s", apiErr.Type)
	}
}

func TestClient_ReturnsAPIError_OnNetworkError(t *testing.T) {
	client := New(&Config{
		APIHost:  "http://127.0.0.1:1",
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	ctx := context.Background()

	_, err := client.GetNodeInfo(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsNetworkError() {
		t.Errorf("expected NetworkError, got type %s", apiErr.Type)
	}
}

func TestClient_304NotModified(t *testing.T) {
	configCalls := 0
	userCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			configCalls++
			if configCalls > 1 {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", "etag-1")
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case "/api/v1/server/UniProxy/user":
			userCalls++
			if userCalls > 1 {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", "etag-2")
			_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
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

	ctx := context.Background()

	node, err := client.GetNodeInfo(ctx)
	if err != nil {
		t.Fatalf("first GetNodeInfo failed: %v", err)
	}
	if node == nil {
		t.Fatal("first GetNodeInfo returned nil")
	}

	node, err = client.GetNodeInfo(ctx)
	if err != nil {
		t.Fatalf("second GetNodeInfo failed: %v", err)
	}
	if node != nil {
		t.Error("expected nil node on 304")
	}

	users, err := client.GetUserList(ctx)
	if err != nil {
		t.Fatalf("first GetUserList failed: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}

	users, err = client.GetUserList(ctx)
	if err != nil {
		t.Fatalf("second GetUserList failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected cached 1 user on 304, got %d", len(users))
	}
}

func TestClient_GetNodeInfo_RejectsMissingServerPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server_name": "test"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetNodeInfo(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
		t.Fatalf("expected parse APIError, got %T: %v", err, err)
	}
}

func TestClient_GetNodeInfo_RejectsZeroServerPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server_port": 0, "server_name": "test"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetNodeInfo(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
		t.Fatalf("expected parse APIError, got %T: %v", err, err)
	}
}

func TestClient_GetNodeInfo_RejectsOutOfRangeServerPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server_port": 65536, "server_name": "bad-port"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetNodeInfo(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
		t.Fatalf("expected parse APIError, got %T: %v", err, err)
	}
}

func TestClient_GetNodeInfo_RejectsImpossibleProtocolValues(t *testing.T) {
	tests := []struct {
		name     string
		nodeType string
		body     string
	}{
		{name: "vmess invalid tls", nodeType: "vmess", body: `{"server_port":443,"tls":99}`},
		{name: "vless invalid tls", nodeType: "vless", body: `{"server_port":443,"tls":-1}`},
		{name: "hysteria negative up", nodeType: "hysteria", body: `{"server_port":443,"up_mbps":-1,"down_mbps":0}`},
		{name: "hysteria2 negative down", nodeType: "hysteria2", body: `{"server_port":443,"up_mbps":0,"down_mbps":-1}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, tt.nodeType)
			_, err := client.GetNodeInfo(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
				t.Fatalf("expected parse APIError, got %T: %v", err, err)
			}
		})
	}
}

func TestClient_GetNodeInfo_AcceptsConservativeProtocolValues(t *testing.T) {
	tests := []struct {
		name     string
		nodeType string
		body     string
	}{
		{name: "vmess none tls", nodeType: "vmess", body: `{"server_port":443,"tls":0}`},
		{name: "vmess tls", nodeType: "vmess", body: `{"server_port":443,"tls":1}`},
		{name: "vless reality", nodeType: "vless", body: `{"server_port":443,"tls":2}`},
		{name: "hysteria zero bandwidth", nodeType: "hysteria", body: `{"server_port":443,"up_mbps":0,"down_mbps":0}`},
		{name: "hysteria2 zero bandwidth", nodeType: "hysteria2", body: `{"server_port":443,"up_mbps":0,"down_mbps":0}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, tt.nodeType)
			_, err := client.GetNodeInfo(context.Background())
			if err != nil {
				t.Fatalf("GetNodeInfo failed: %v", err)
			}
		})
	}
}

func TestClient_GetUserList_BodyHashDedup(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("ETag", "etag-"+string(rune('0'+callCount)))
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}, {"id": 2, "uuid": "550e8400-e29b-41d4-a716-446655440001"}]}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	ctx := context.Background()

	users, err := client.GetUserList(ctx)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	// Second call: same body but different ETag → should dedup via hash
	users, err = client.GetUserList(ctx)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected cached 2 users via hash dedup, got %d", len(users))
	}
}

func TestClient_CachedUserListReturnsCopy(t *testing.T) {
	client := New(&Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: "vless"})
	client.userList = &UserListBody{Users: []UserInfo{{Id: 1, Uuid: "550e8400-e29b-41d4-a716-446655440000"}}}

	users := client.CachedUserList()
	users[0].Uuid = "mutated"

	if client.userList.Users[0].Uuid != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("cached uuid = %q, want 550e8400-e29b-41d4-a716-446655440000", client.userList.Users[0].Uuid)
	}
}

func TestClient_CachedUserListNilCache(t *testing.T) {
	client := New(&Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: "vless"})
	client.userList = nil
	if users := client.CachedUserList(); users != nil {
		t.Fatalf("users = %#v, want nil", users)
	}
}

func TestClient_GetUserList_RejectsInvalidUsers(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "zero id", body: `{"users": [{"id": 0, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`},
		{name: "negative id", body: `{"users": [{"id": -1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`},
		{name: "empty uuid", body: `{"users": [{"id": 1, "uuid": ""}]}`},
		{name: "negative speed limit", body: `{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000", "speed_limit": -1}]}`},
		{name: "negative device limit", body: `{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000", "device_limit": -1}]}`},
		{name: "duplicate id", body: `{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}, {"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440001"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			_, err := client.GetUserList(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
				t.Fatalf("expected parse APIError, got %T: %v", err, err)
			}
			if cached := client.CachedUserList(); cached != nil {
				t.Fatalf("cached users = %#v, want nil", cached)
			}
		})
	}
}

func TestClient_GetUserList_ReturnsCopyOnFreshAndCachedResponses(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount > 1 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set(headerETag, "etag-1")
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	users, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("first GetUserList failed: %v", err)
	}
	users[0].Uuid = "mutated"

	cached, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("cached GetUserList failed: %v", err)
	}
	if cached[0].Uuid != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("cached uuid = %q, want 550e8400-e29b-41d4-a716-446655440000", cached[0].Uuid)
	}
}

func TestClient_RetriesGetButNotPost(t *testing.T) {
	configCalls := 0
	pushCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			configCalls++
			if configCalls == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case "/api/v1/server/UniProxy/push":
			pushCalls++
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	if _, err := client.GetNodeInfo(context.Background()); err != nil {
		t.Fatalf("GetNodeInfo should retry and succeed: %v", err)
	}
	if configCalls != 2 {
		t.Fatalf("config calls = %d, want 2", configCalls)
	}

	err := client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}})
	if err == nil {
		t.Fatal("expected ReportUserTraffic error")
	}
	if pushCalls != 1 {
		t.Fatalf("push calls = %d, want 1", pushCalls)
	}
}

func TestClient_GetNodeInfo_ParseErrorDoesNotCommitCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("ETag", "etag-bad")
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	if _, err := client.GetNodeInfo(context.Background()); err == nil {
		t.Fatal("expected first parse error")
	}
	if _, err := client.GetNodeInfo(context.Background()); err == nil {
		t.Fatal("expected second parse error")
	}
	if callCount != 2 {
		t.Fatalf("call count = %d, want 2", callCount)
	}
}

func TestClient_GetUserList_BodyHashDedupRefreshesETag(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 3 {
			if got := r.Header.Get(headerIfNoneMatch); got != "etag-2" {
				t.Fatalf("If-None-Match = %q, want etag-2", got)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "etag-"+string(rune('0'+callCount)))
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	for i := 0; i < 3; i++ {
		users, err := client.GetUserList(context.Background())
		if err != nil {
			t.Fatalf("GetUserList call %d failed: %v", i+1, err)
		}
		if len(users) != 1 {
			t.Fatalf("users count = %d, want 1", len(users))
		}
	}
}

func TestClient_GetUserList_BodyHashDedupKeepsETagWhenMissing(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1:
			w.Header().Set(headerETag, "etag-1")
		case 3:
			if got := r.Header.Get(headerIfNoneMatch); got != "etag-1" {
				t.Fatalf("If-None-Match = %q, want etag-1", got)
			}
		}
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	for i := 0; i < 3; i++ {
		users, err := client.GetUserList(context.Background())
		if err != nil {
			t.Fatalf("GetUserList call %d failed: %v", i+1, err)
		}
		if len(users) != 1 {
			t.Fatalf("users count = %d, want 1", len(users))
		}
	}
}

func TestClient_GetNodeInfo_KeepsETagWhenMissing(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1:
			w.Header().Set(headerETag, "etag-1")
		case 3:
			if got := r.Header.Get(headerIfNoneMatch); got != "etag-1" {
				t.Fatalf("If-None-Match = %q, want etag-1", got)
			}
		}
		_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	for i := 0; i < 3; i++ {
		_, err := client.GetNodeInfo(context.Background())
		if err != nil {
			t.Fatalf("GetNodeInfo call %d failed: %v", i+1, err)
		}
	}
}

func TestClient_GetNodeInfo_BodyHashDedupRefreshesETag(t *testing.T) {
	callCount := 0
	var requestErrors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 3 {
			if got := r.Header.Get(headerIfNoneMatch); got != "etag-2" {
				requestErrors = append(requestErrors, fmt.Sprintf("If-None-Match = %q, want etag-2", got))
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set(headerETag, "etag-"+string(rune('0'+callCount)))
		_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	first, err := client.GetNodeInfo(context.Background())
	if err != nil {
		t.Fatalf("first GetNodeInfo failed: %v", err)
	}
	if first == nil {
		t.Fatal("first GetNodeInfo returned nil")
	}
	second, err := client.GetNodeInfo(context.Background())
	if err != nil {
		t.Fatalf("second GetNodeInfo failed: %v", err)
	}
	if second != nil {
		t.Fatalf("second GetNodeInfo = %#v, want nil for unchanged body", second)
	}
	third, err := client.GetNodeInfo(context.Background())
	if err != nil {
		t.Fatalf("third GetNodeInfo failed: %v", err)
	}
	if third != nil {
		t.Fatalf("third GetNodeInfo = %#v, want nil for 304", third)
	}
	if len(requestErrors) > 0 {
		t.Fatalf("request errors: %s", strings.Join(requestErrors, "; "))
	}
}

func TestClient_GetWithRetryWaitsBetweenServerErrors(t *testing.T) {
	callCount := 0
	var previousCall time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 2 && time.Since(previousCall) < 5*time.Millisecond {
			t.Fatalf("retry happened without backoff")
		}
		previousCall = time.Now()
		if callCount == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	if _, err := client.GetNodeInfo(context.Background()); err != nil {
		t.Fatalf("GetNodeInfo failed: %v", err)
	}
	if callCount != 2 {
		t.Fatalf("call count = %d, want 2", callCount)
	}
}

func TestClient_GetWithRetryReturnsErrorAfterServerErrorRetriesExhausted(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetNodeInfo(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if callCount != getRetryCount+1 {
		t.Fatalf("call count = %d, want %d", callCount, getRetryCount+1)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 APIError, got %T: %v", err, err)
	}
}

func TestClient_GetWithRetryStopsWhenContextCanceledAfterFailedAttempt(t *testing.T) {
	callCount := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		cancel()
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetNodeInfo(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if callCount != 1 {
		t.Fatalf("call count = %d, want 1", callCount)
	}
}

func TestClient_ReportNodeOnlineUsers_PostsAlivePayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != apiAlivePath {
			t.Fatalf("path = %q, want %q", r.URL.Path, apiAlivePath)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != contentTypeJSON {
			t.Fatalf("Content-Type = %q, want %q", got, contentTypeJSON)
		}

		var body map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		ips := body[1]
		if len(ips) != 2 || ips[0] != "203.0.113.1_1" || ips[1] != "203.0.113.2_1" {
			t.Fatalf("body[1] = %#v", ips)
		}
		_, _ = w.Write([]byte(`{"data": true}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	err := client.ReportNodeOnlineUsers(context.Background(), map[int][]string{
		1: {"203.0.113.1_1", "203.0.113.2_1"},
	})
	if err != nil {
		t.Fatalf("ReportNodeOnlineUsers failed: %v", err)
	}
}

func TestClient_GetUserList_ParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetUserList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
		t.Fatalf("expected parse APIError, got %T: %v", err, err)
	}
}

func TestClient_GetUserList_ParseErrorDoesNotCommitCache(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("ETag", "bad-etag")
			_, _ = w.Write([]byte(`not valid json`))
			return
		}
		w.Header().Set("ETag", "good-etag")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	if _, err := client.GetUserList(context.Background()); err == nil {
		t.Fatal("expected parse error")
	}
	users, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("second GetUserList failed: %v", err)
	}
	if len(users) != 1 || users[0].Uuid != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("users = %#v", users)
	}
	if client.userEtag != "good-etag" {
		t.Fatalf("userEtag = %q, want good-etag", client.userEtag)
	}
}

func TestClient_GetUserList_304WithoutCacheReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	users, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("GetUserList failed: %v", err)
	}
	if users != nil {
		t.Fatalf("users = %#v, want nil", users)
	}
}

func TestClient_GetRequestsUseConstructionSnapshot(t *testing.T) {
	requestCount := 0
	var requestErrors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if got := r.URL.Query().Get("token"); got != "token" {
			requestErrors = append(requestErrors, fmt.Sprintf("token query = %q", got))
		}
		if got := r.URL.Query().Get("node_id"); got != "7" {
			requestErrors = append(requestErrors, fmt.Sprintf("node_id query = %q", got))
		}
		if got := r.URL.Query().Get("node_type"); got != "vless" {
			requestErrors = append(requestErrors, fmt.Sprintf("node_type query = %q", got))
		}
		if requestCount == 1 && r.Header.Get(headerIfNoneMatch) != "" {
			requestErrors = append(requestErrors, fmt.Sprintf("first If-None-Match = %q", r.Header.Get(headerIfNoneMatch)))
		}
		if requestCount == 2 && r.Header.Get(headerIfNoneMatch) != "etag-1" {
			requestErrors = append(requestErrors, fmt.Sprintf("second If-None-Match = %q", r.Header.Get(headerIfNoneMatch)))
		}
		w.Header().Set(headerETag, "etag-1")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{APIHost: server.URL, Key: "token", NodeID: 7, NodeType: "vless", Timeout: 1})
	client.Token = "mutated-token"
	client.NodeId = 99
	client.NodeType = "vmess"
	client.APIHost = "http://127.0.0.1:1"

	if _, err := client.GetUserList(context.Background()); err != nil {
		t.Fatalf("first GetUserList failed: %v", err)
	}
	if _, err := client.GetUserList(context.Background()); err != nil {
		t.Fatalf("second GetUserList failed: %v", err)
	}
	if len(requestErrors) > 0 {
		t.Fatalf("request errors: %s", strings.Join(requestErrors, "; "))
	}
}

func TestClient_GetNodeInfoUsesConstructionSnapshot(t *testing.T) {
	var requestErrors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("node_type"); got != "vless" {
			requestErrors = append(requestErrors, fmt.Sprintf("node_type query = %q", got))
		}
		if got := r.URL.Query().Get("node_id"); got != "7" {
			requestErrors = append(requestErrors, fmt.Sprintf("node_id query = %q", got))
		}
		_, _ = w.Write([]byte(`{"server_port":443,"tls":2,"server_name":"example.com","network":"tcp","encryption":"none"}`))
	}))
	defer server.Close()

	client := New(&Config{APIHost: server.URL, Key: "token", NodeID: 7, NodeType: "vless", Timeout: 1})
	client.NodeType = "vmess"
	client.NodeId = 99

	node, err := client.GetNodeInfo(context.Background())
	if err != nil {
		t.Fatalf("GetNodeInfo failed: %v", err)
	}
	if node.Type != "vless" || node.Id != 7 || node.Vless == nil {
		t.Fatalf("node = %#v, want construction snapshot vless node 7", node)
	}
	if len(requestErrors) > 0 {
		t.Fatalf("request errors: %s", strings.Join(requestErrors, "; "))
	}
}

func TestClient_CachedUserListDoesNotWaitForUserFetch(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	closeRelease := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()
	defer closeRelease()

	client := newTestClient(t, server.URL, "vless")
	client.userList = &UserListBody{Users: []UserInfo{{Id: 1, Uuid: "cached"}}}

	fetchDone := make(chan error, 1)
	go func() {
		_, err := client.GetUserList(context.Background())
		fetchDone <- err
	}()
	<-started

	cacheDone := make(chan []UserInfo, 1)
	go func() {
		cacheDone <- client.CachedUserList()
	}()

	select {
	case users := <-cacheDone:
		if len(users) != 1 || users[0].Uuid != "cached" {
			t.Fatalf("cached users = %#v", users)
		}
		closeRelease()
	case <-time.After(50 * time.Millisecond):
		t.Fatal("CachedUserList waited for in-flight GetUserList network request")
	}

	select {
	case err := <-fetchDone:
		if err != nil {
			t.Fatalf("GetUserList failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GetUserList did not finish after release")
	}
}

func TestClient_ReportUserTraffic_RejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name    string
		traffic []UserTraffic
	}{
		{name: "zero uid", traffic: []UserTraffic{{UID: 0, Upload: 1, Download: 1}}},
		{name: "negative uid", traffic: []UserTraffic{{UID: -1, Upload: 1, Download: 1}}},
		{name: "negative upload", traffic: []UserTraffic{{UID: 1, Upload: -1, Download: 1}}},
		{name: "negative download", traffic: []UserTraffic{{UID: 1, Upload: 1, Download: -1}}},
		{name: "duplicate uid", traffic: []UserTraffic{{UID: 1, Upload: 1, Download: 1}, {UID: 1, Upload: 2, Download: 2}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			err := client.ReportUserTraffic(context.Background(), tt.traffic)
			if err == nil {
				t.Fatal("expected error")
			}
			if called {
				t.Fatal("server was called for invalid payload")
			}
		})
	}
}

func TestClient_ReportUserTraffic_EmptyPayloadIsNoop(t *testing.T) {
	tests := []struct {
		name    string
		traffic []UserTraffic
	}{
		{name: "nil traffic", traffic: nil},
		{name: "empty traffic", traffic: []UserTraffic{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			if err := client.ReportUserTraffic(context.Background(), tt.traffic); err != nil {
				t.Fatalf("ReportUserTraffic failed: %v", err)
			}
			if called {
				t.Fatal("server was called for empty traffic")
			}
		})
	}
}

func TestCloneOnlineUsers_DoesNotShareCallerMapOrSlices(t *testing.T) {
	data := map[int][]string{1: {"203.0.113.1_1"}}

	cloned := cloneOnlineUsers(data)
	data[1][0] = "not-ip_1"
	data[2] = []string{"203.0.113.2_1"}

	if got := cloned[1]; len(got) != 1 || got[0] != "203.0.113.1_1" {
		t.Fatalf("cloned[1] = %#v", got)
	}
	if _, ok := cloned[2]; ok {
		t.Fatalf("cloned contains later caller map mutation: %#v", cloned)
	}
}

func TestClient_ReportNodeOnlineUsers_RejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name string
		data map[int][]string
	}{
		{name: "nil data", data: nil},
		{name: "zero uid", data: map[int][]string{0: {"203.0.113.1_1"}}},
		{name: "negative uid", data: map[int][]string{-1: {"203.0.113.1_1"}}},
		{name: "empty users", data: map[int][]string{1: {}}},
		{name: "empty user entry", data: map[int][]string{1: {""}}},
		{name: "invalid ip", data: map[int][]string{1: {"not-ip_1"}}},
		{name: "empty suffix", data: map[int][]string{1: {"203.0.113.1_"}}},
		{name: "empty ip", data: map[int][]string{1: {"_1"}}},
		{name: "multiple separators", data: map[int][]string{1: {"203.0.113.1_1_2"}}},
		{name: "non-numeric suffix", data: map[int][]string{1: {"203.0.113.1_bad"}}},
		{name: "blank suffix", data: map[int][]string{1: {"203.0.113.1_  "}}},
		{name: "leading space in ip", data: map[int][]string{1: {" 203.0.113.1_1"}}},
		{name: "leading space in suffix", data: map[int][]string{1: {"203.0.113.1_ 1"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			err := client.ReportNodeOnlineUsers(context.Background(), tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if called {
				t.Fatal("server was called for invalid payload")
			}
		})
	}
}

func TestClient_ReportNodeOnlineUsers_EmptyMapPostsPayload(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != apiAlivePath {
			t.Fatalf("path = %q, want %q", r.URL.Path, apiAlivePath)
		}
		var body map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if len(body) != 0 {
			t.Fatalf("body = %#v, want empty map", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	if err := client.ReportNodeOnlineUsers(context.Background(), map[int][]string{}); err != nil {
		t.Fatalf("ReportNodeOnlineUsers failed: %v", err)
	}
	if !called {
		t.Fatal("server was not called for empty online users")
	}
}

func TestClient_ReportUserTraffic_PostsPushPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != apiPushPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, apiPushPath)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		var body map[int][]int64
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		got := body[1]
		if len(got) != 2 || got[0] != 10 || got[1] != 20 {
			t.Fatalf("body[1] = %#v", got)
		}
		_, _ = w.Write([]byte(`{"data": true}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	err := client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}})
	if err != nil {
		t.Fatalf("ReportUserTraffic failed: %v", err)
	}
}

func TestClient_GetAliveList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alivelist" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"alive": {"1": 3, "2": 1, "5": 0}}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	ctx := context.Background()
	alive, err := client.GetAliveList(ctx)
	if err != nil {
		t.Fatalf("GetAliveList failed: %v", err)
	}
	if alive[1] != 3 {
		t.Errorf("alive[1] = %d, want 3", alive[1])
	}
	if alive[2] != 1 {
		t.Errorf("alive[2] = %d, want 1", alive[2])
	}
	if alive[5] != 0 {
		t.Errorf("alive[5] = %d, want 0", alive[5])
	}
}

func TestClient_GetAliveList_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`internal error`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	_, err := client.GetAliveList(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if !apiErr.IsServerError() {
		t.Errorf("expected server error, got type %s", apiErr.Type)
	}
}

func TestClient_GetAliveList_ParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetAliveList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
		t.Fatalf("expected parse APIError, got %T: %v", err, err)
	}
}

func TestClient_GetAliveList_Empty(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty object", body: `{"alive": {}}`},
		{name: "missing alive", body: `{}`},
		{name: "null alive", body: `{"alive": null}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := New(&Config{
				APIHost:  server.URL,
				Key:      "test-token",
				NodeID:   1,
				NodeType: "vless",
				Timeout:  1,
			})

			alive, err := client.GetAliveList(context.Background())
			if err != nil {
				t.Fatalf("GetAliveList failed: %v", err)
			}
			if alive == nil {
				t.Fatal("alive map is nil")
			}
			if len(alive) != 0 {
				t.Errorf("expected empty map, got %d entries", len(alive))
			}
		})
	}
}

func TestClient_GetAliveList_RejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "negative uid", body: `{"alive": {"-1": 1}}`},
		{name: "negative count", body: `{"alive": {"1": -1}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			_, err := client.GetAliveList(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
				t.Fatalf("expected parse APIError, got %T: %v", err, err)
			}
		})
	}
}
