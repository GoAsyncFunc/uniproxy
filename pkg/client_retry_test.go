package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

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
	if err := client.ReportNodeOnlineUsers(ctx, map[int][]netip.Addr{1: {netip.MustParseAddr("203.0.113.1")}}); err != nil {
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

func TestClient_RetriesGetButNotPost(t *testing.T) {
	configCalls := 0
	pushCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case apiConfigPath:
			configCalls++
			if configCalls == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_, _ = w.Write([]byte(`{"server_port": 1234, "server_name": "test"}`))
		case apiPushPath:
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
