package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_RefreshWaitRespectsContext(t *testing.T) {
	for _, kind := range []string{"node", "users"} {
		t.Run(kind, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var startOnce sync.Once
			var releaseOnce sync.Once
			var calls atomic.Int32
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				startOnce.Do(func() { close(started) })
				<-release
				if kind == "node" {
					_, _ = writer.Write([]byte(`{"server_port":443}`))
				} else {
					_, _ = writer.Write([]byte(`{"users":[]}`))
				}
			}))
			defer server.Close()
			defer unblock()

			client := newTestClient(t, server.URL, "vless")
			client.client.SetTimeout(5 * time.Second)
			fetch := func(ctx context.Context) error {
				if kind == "node" {
					_, err := client.GetNodeInfo(ctx)
					return err
				}
				_, err := client.GetUserList(ctx)
				return err
			}
			first := make(chan error, 1)
			go func() { first <- fetch(context.Background()) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("first refresh did not start")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			second := make(chan error, 1)
			go func() { second <- fetch(ctx) }()
			select {
			case err := <-second:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error = %v, want deadline exceeded", err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("canceled refresh is still waiting for the in-flight request")
			}
			if calls.Load() != 1 {
				t.Fatalf("requests = %d, want only the first refresh", calls.Load())
			}

			unblock()
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			if err := fetch(context.Background()); err != nil {
				t.Fatalf("refresh after cancellation failed: %v", err)
			}
			canceled, stop := context.WithCancel(context.Background())
			stop()
			if err := fetch(canceled); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want canceled", err)
			}
			if calls.Load() != 2 {
				t.Fatalf("requests = %d, want no request for canceled context", calls.Load())
			}
		})
	}
}
