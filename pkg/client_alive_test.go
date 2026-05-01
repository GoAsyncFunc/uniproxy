package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_GetAliveList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != apiAliveListPath {
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
