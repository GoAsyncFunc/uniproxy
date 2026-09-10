package pkg

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	resty "github.com/go-resty/resty/v2"
)

func TestShouldRetryGet(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "canceled", err: fmt.Errorf("wrapped: %w", context.Canceled)},
		{name: "oversized body", err: fmt.Errorf("wrapped: %w", resty.ErrResponseBodyTooLarge)},
		{name: "unknown error", err: errors.New("invalid request")},
		{name: "invalid certificate", err: &url.Error{Op: "Get", Err: x509.UnknownAuthorityError{}}},
		{name: "missing DNS name", err: &net.DNSError{IsNotFound: true}},
		{name: "temporary DNS failure", err: &net.DNSError{IsTemporary: true}, want: true},
		{name: "DNS timeout", err: &net.DNSError{IsTimeout: true}, want: true},
		{name: "connection failure", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, want: true},
		{name: "client timeout", err: &url.Error{Op: "Get", Err: context.DeadlineExceeded}, want: true},
		{name: "EOF", err: io.EOF, want: true},
		{name: "unexpected EOF", err: fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldRetryGet(nil, test.err); got != test.want {
				t.Fatalf("retry = %t, want %t", got, test.want)
			}
		})
	}
	if shouldRetryGet(nil, nil) {
		t.Fatal("nil response must not retry")
	}
	for _, status := range []int{200, 204, 301, 304, 400, 401, 403, 404, 429, 500, 501, 502, 503, 504, 505} {
		t.Run(fmt.Sprintf("HTTP_%d", status), func(t *testing.T) {
			response := &resty.Response{RawResponse: &http.Response{StatusCode: status}}
			want := status == 500 || status == 502 || status == 503 || status == 504
			if got := shouldRetryGet(response, nil); got != want {
				t.Fatalf("retry = %t, want %t", got, want)
			}
		})
	}
}

func TestGetRetryDelayUsesExponentialJitter(t *testing.T) {
	for attempt := 0; attempt < getRetryCount; attempt++ {
		minimum := getRetryBackoff << attempt
		for sample := 0; sample < 100; sample++ {
			delay := getRetryDelay(attempt)
			if delay < minimum || delay >= 2*minimum {
				t.Fatalf("attempt %d delay = %s, want [%s, %s)", attempt, delay, minimum, 2*minimum)
			}
		}
	}
}

func TestClient_OversizedResponseDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	body := strings.Repeat("x", maxResponseBodyBytes+1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(writer, body)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetUserList(context.Background())
	if !errors.Is(err, resty.ErrResponseBodyTooLarge) {
		t.Fatalf("error = %v, want response body too large", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("requests = %d, want one request", calls.Load())
	}
}

func TestClient_GetWithRetryCancelsDuringBackoff(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, "vless")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.client.OnAfterResponse(func(_ *resty.Client, _ *resty.Response) error {
		time.AfterFunc(10*time.Millisecond, cancel)
		return nil
	})
	_, err := client.GetUserList(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want canceled", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("requests = %d, want cancellation before retry", calls.Load())
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
