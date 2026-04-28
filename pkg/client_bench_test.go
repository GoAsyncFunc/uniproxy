package pkg

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func BenchmarkGetUserListParse(b *testing.B) {
	for _, userCount := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("users_%d", userCount), func(b *testing.B) {
			body := benchmarkUserListBody(userCount)
			etag := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				etag++
				w.Header().Set("ETag", fmt.Sprintf("etag-%d", etag))
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			client := New(&Config{APIHost: server.URL, Key: "token", NodeID: 1, NodeType: "vless", Timeout: 1})
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				client.userBodyHash = ""
				client.userEtag = ""
				users, err := client.GetUserList(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if len(users) != userCount {
					b.Fatalf("users=%d want=%d", len(users), userCount)
				}
			}
		})
	}
}

func BenchmarkGetUserListHashDedup(b *testing.B) {
	body := benchmarkUserListBody(10000)
	etag := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag++
		w.Header().Set("ETag", fmt.Sprintf("etag-%d", etag))
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := New(&Config{APIHost: server.URL, Key: "token", NodeID: 1, NodeType: "vless", Timeout: 1})
	ctx := context.Background()
	if _, err := client.GetUserList(ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		users, err := client.GetUserList(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if len(users) != 10000 {
			b.Fatalf("users=%d want=10000", len(users))
		}
	}
}

func BenchmarkGetUserListNotModified(b *testing.B) {
	body := benchmarkUserListBody(10000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerIfNoneMatch) != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "etag-1")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := New(&Config{APIHost: server.URL, Key: "token", NodeID: 1, NodeType: "vless", Timeout: 1})
	ctx := context.Background()
	if _, err := client.GetUserList(ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		users, err := client.GetUserList(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if len(users) != 10000 {
			b.Fatalf("users=%d want=10000", len(users))
		}
	}
}

func benchmarkUserListBody(count int) string {
	var b strings.Builder
	b.Grow(count * 48)
	b.WriteString(`{"users":[`)
	for i := 0; i < count; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%d,"uuid":"uuid-%d","speed_limit":0,"device_limit":0}`, i+1, i+1)
	}
	b.WriteString(`]}`)
	return b.String()
}
