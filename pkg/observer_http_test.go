package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	resty "github.com/go-resty/resty/v2"
)

func TestObserverRealHTTPContracts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		outcome    RequestOutcome
		parseError bool
		tooLarge   bool
	}{
		{name: "invalid JSON", status: 200, body: "not-json", outcome: RequestSucceeded, parseError: true},
		{name: "unsolicited 304", status: 304, outcome: RequestNotModified, parseError: true},
		{name: "oversized", status: 200, body: strings.Repeat("x", maxResponseBodyBytes+1), outcome: RequestResponseTooLarge, tooLarge: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			var events []RequestEvent
			client, err := NewWithError(&Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: Vless, Observer: func(e RequestEvent) { events = append(events, e) }})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			_, err = client.GetUserList(context.Background())
			if tc.parseError {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
					t.Fatalf("expected parse error: %v", err)
				}
			}
			if tc.tooLarge && !errors.Is(err, resty.ErrResponseBodyTooLarge) {
				t.Fatalf("expected body limit error: %v", err)
			}
			if len(events) != 1 || events[0].Outcome != tc.outcome || events[0].StatusCode != tc.status || events[0].Path != apiUserPath || events[0].Attempt != 1 {
				t.Fatalf("unexpected events: %+v", events)
			}
		})
	}
}

func TestObserverRealCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			defer server.Close()
			defer close(release)
			var events []RequestEvent
			client, err := NewWithError(&Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: Vless, Timeout: 5, Observer: func(e RequestEvent) { events = append(events, e) }})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := client.GetUserList(ctx); done <- err }()
			select {
			case <-started:
			case err := <-done:
				t.Fatalf("request ended before handler: %v", err)
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("handler not reached")
			}
			want := RequestCanceled
			target := context.Canceled
			if deadline {
				want = RequestDeadlineExceeded
				target = context.DeadlineExceeded
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, target) {
					t.Fatalf("unexpected error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("request failed to cancel")
			}
			if len(events) != 1 || events[0].Outcome != want || events[0].StatusCode != 0 {
				t.Fatalf("unexpected events: %+v", events)
			}
		})
	}
}

func TestObserverOnlineAcknowledgementFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"data":false}`)) }))
	defer server.Close()
	var events []RequestEvent
	client, err := NewWithError(&Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: Vless, Observer: func(e RequestEvent) { events = append(events, e) }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	err = client.ReportNodeOnlineUsers(context.Background(), map[int][]netip.Addr{1: {}})
	if err == nil {
		t.Fatal("expected negative acknowledgement error")
	}
	if len(events) != 1 || events[0].Method != http.MethodPost || events[0].Path != apiAlivePath || events[0].Outcome != RequestSucceeded || events[0].Attempt != 1 {
		t.Fatalf("unexpected events: %+v", events)
	}
}
