package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	resty "github.com/go-resty/resty/v2"
)

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

func TestClient_CheckResponseRedactsAndTruncatesErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("token=secret-token&node_id=1\n" + strings.Repeat("x", 12*1024)))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")

	_, err := client.GetAliveList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if strings.Contains(got, "secret-token") {
		t.Fatalf("error leaked token: %q", got)
	}
	if !strings.Contains(got, "token=REDACTED") {
		t.Fatalf("error = %q, want redacted token marker", got)
	}
	if len(got) > 9*1024 {
		t.Fatalf("error length = %d, want truncated error", len(got))
	}
}

func TestClient_CheckResponseRedactsJSONAndHeaderSecrets(t *testing.T) {
	body := strings.Join([]string{
		`{"token":"secret-token","client_secret":"client-secret","message":"failed"}`,
		`{"authorization":"Bearer quoted-bearer-secret"}`,
		`{"Authorization":"Bearer upper-bearer-secret"}`,
		"Authorization: Bearer bearer-secret",
		"X-Api-Key: api-key-secret",
		"authorization=Bearer form-secret",
	}, "\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")

	_, err := client.GetAliveList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	for _, secret := range []string{"secret-token", "client-secret", "quoted-bearer-secret", "upper-bearer-secret", "bearer-secret", "api-key-secret", "form-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("error leaked %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "message") {
		t.Fatalf("error = %q, want non-secret message preserved", got)
	}
}

func TestClient_CheckResponseRejectsOversizedErrorBodyWithoutIncludingContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBodyBytes) + "token=secret-token"))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")

	_, err := client.GetAliveList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if !strings.Contains(got, "response body too large") {
		t.Fatalf("error = %q, want response body too large", got)
	}
	if strings.Contains(got, "secret-token") {
		t.Fatalf("error leaked oversized body secret: %q", got)
	}
	if len(got) > 1024 {
		t.Fatalf("error length = %d, want no oversized body content", len(got))
	}
}

func TestClient_RejectsOversizedResponseBody(t *testing.T) {
	tests := []struct {
		name string
		path string
		call func(*Client) error
	}{
		{
			name: "node config",
			path: apiConfigPath,
			call: func(client *Client) error {
				_, err := client.GetNodeInfo(context.Background())
				return err
			},
		},
		{
			name: "user list",
			path: apiUserPath,
			call: func(client *Client) error {
				_, err := client.GetUserList(context.Background())
				return err
			},
		},
		{
			name: "alive list",
			path: apiAliveListPath,
			call: func(client *Client) error {
				_, err := client.GetAliveList(context.Background())
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBodyBytes+1)))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")

			err := tt.call(client)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "response body too large") {
				t.Fatalf("error = %q, want response body too large", err.Error())
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || !errors.Is(apiErr.Err, resty.ErrResponseBodyTooLarge) {
				t.Fatalf("error = %T: %v, want wrapped resty.ErrResponseBodyTooLarge", err, err)
			}
		})
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
