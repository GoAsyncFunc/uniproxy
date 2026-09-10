package pkg

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
)

func TestClientTransportLoopback(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, bind := range []bool{false, true} {
			name := network
			if bind {
				name += "/bound"
			}
			t.Run(name, func(t *testing.T) {
				host := "127.0.0.1"
				if network == "tcp6" {
					host = "::1"
				}
				listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
				if err != nil {
					if network == "tcp6" {
						t.Skipf("IPv6 loopback unavailable: %v", err)
					}
					t.Fatal(err)
				}
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					remote, _, err := net.SplitHostPort(r.RemoteAddr)
					if err != nil || remote != host {
						t.Errorf("unexpected source address %q", r.RemoteAddr)
					}
					_, _ = w.Write([]byte(`{"users":[]}`))
				}))
				_ = server.Listener.Close()
				server.Listener = listener
				server.Start()
				defer server.Close()
				config := &Config{APIHost: server.URL, Key: "token", NodeID: 1, NodeType: Vless, Timeout: 2}
				if bind {
					config.APISendIP = host
				}
				client, err := NewWithError(config)
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				if _, err := client.GetUserList(context.Background()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestClientCloseIdleConnectionsPreservesCacheAndReuse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerIfNoneMatch) == `"users"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set(headerETag, `"users"`)
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, Vless)
	defer client.CloseIdleConnections()
	fetch := func(wantReused bool) {
		t.Helper()
		var reused, called atomic.Bool
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { called.Store(true); reused.Store(info.Reused) }})
		users, err := client.GetUserList(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(users) != 1 || !called.Load() || reused.Load() != wantReused {
			t.Fatalf("users=%d connection reused=%t, want %t", len(users), reused.Load(), wantReused)
		}
	}
	fetch(false)
	fetch(true)
	client.CloseIdleConnections()
	client.CloseIdleConnections()
	fetch(false)
	fetch(true)
}

func TestClientCloseIdleConnectionsDoesNotInterruptActiveRequest(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte(`{"users":[]}`))
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, Vless)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.GetUserList(ctx); done <- err }()
	select {
	case <-started:
		client.CloseIdleConnections()
		close(release)
	case err := <-done:
		close(release)
		t.Fatalf("request failed before reaching handler: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
