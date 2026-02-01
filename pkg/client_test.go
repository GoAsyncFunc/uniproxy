package pkg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestClient_Concurrency(t *testing.T) {
	// Mock server
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

	// Concurrent read/write test
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
