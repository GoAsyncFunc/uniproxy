package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestClient_Concurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			w.Header().Set("ETag", "123")
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case "/api/v1/server/UniProxy/user":
			w.Header().Set("ETag", "456")
			_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "test-uuid"}]}`))
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
			_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "test-uuid"}]}`))
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
