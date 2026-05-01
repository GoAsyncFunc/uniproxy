package pkg

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_304NotModified(t *testing.T) {
	configCalls := 0
	userCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case apiConfigPath:
			configCalls++
			if configCalls > 1 {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", "etag-1")
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case apiUserPath:
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

func TestClient_GetNodeInfoUsesConstructionSnapshot(t *testing.T) {
	var requestErrors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("token"); got != "token" {
			requestErrors = append(requestErrors, fmt.Sprintf("token query = %q", got))
		}
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
	client.Token = "mutated-token"

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
