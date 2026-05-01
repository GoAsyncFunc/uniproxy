package pkg

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClient_GetUserList_BodyHashDedup(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("ETag", "etag-"+string(rune('0'+callCount)))
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}, {"id": 2, "uuid": "550e8400-e29b-41d4-a716-446655440001"}]}`))
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

	users, err := client.GetUserList(ctx)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	// Second call: same body but different ETag → should dedup via hash
	users, err = client.GetUserList(ctx)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected cached 2 users via hash dedup, got %d", len(users))
	}
}

func TestClient_CachedUserListReturnsCopy(t *testing.T) {
	client := New(&Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: "vless"})
	client.userList = &UserListBody{Users: []UserInfo{{Id: 1, Uuid: "550e8400-e29b-41d4-a716-446655440000"}}}

	users := client.CachedUserList()
	users[0].Uuid = "mutated"

	if client.userList.Users[0].Uuid != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("cached uuid = %q, want 550e8400-e29b-41d4-a716-446655440000", client.userList.Users[0].Uuid)
	}
}

func TestClient_CachedUserListNilCache(t *testing.T) {
	client := New(&Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: "vless"})
	client.userList = nil
	if users := client.CachedUserList(); users != nil {
		t.Fatalf("users = %#v, want nil", users)
	}
}

func TestClient_GetUserList_RejectsInvalidUsers(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "zero id", body: `{"users": [{"id": 0, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`},
		{name: "negative id", body: `{"users": [{"id": -1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`},
		{name: "empty uuid", body: `{"users": [{"id": 1, "uuid": ""}]}`},
		{name: "negative speed limit", body: `{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000", "speed_limit": -1}]}`},
		{name: "negative device limit", body: `{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000", "device_limit": -1}]}`},
		{name: "duplicate id", body: `{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}, {"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440001"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			_, err := client.GetUserList(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
				t.Fatalf("expected parse APIError, got %T: %v", err, err)
			}
			if cached := client.CachedUserList(); cached != nil {
				t.Fatalf("cached users = %#v, want nil", cached)
			}
		})
	}
}

func TestClient_GetUserList_ReturnsCopyOnFreshAndCachedResponses(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount > 1 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set(headerETag, "etag-1")
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	users, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("first GetUserList failed: %v", err)
	}
	users[0].Uuid = "mutated"

	cached, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("cached GetUserList failed: %v", err)
	}
	if cached[0].Uuid != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("cached uuid = %q, want 550e8400-e29b-41d4-a716-446655440000", cached[0].Uuid)
	}
}

func TestClient_GetUserList_BodyHashDedupRefreshesETag(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 3 {
			if got := r.Header.Get(headerIfNoneMatch); got != "etag-2" {
				t.Fatalf("If-None-Match = %q, want etag-2", got)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "etag-"+string(rune('0'+callCount)))
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	for i := 0; i < 3; i++ {
		users, err := client.GetUserList(context.Background())
		if err != nil {
			t.Fatalf("GetUserList call %d failed: %v", i+1, err)
		}
		if len(users) != 1 {
			t.Fatalf("users count = %d, want 1", len(users))
		}
	}
}

func TestClient_GetUserList_BodyHashDedupKeepsETagWhenMissing(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1:
			w.Header().Set(headerETag, "etag-1")
		case 3:
			if got := r.Header.Get(headerIfNoneMatch); got != "etag-1" {
				t.Fatalf("If-None-Match = %q, want etag-1", got)
			}
		}
		_, _ = w.Write([]byte(`{"users": [{"id": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	for i := 0; i < 3; i++ {
		users, err := client.GetUserList(context.Background())
		if err != nil {
			t.Fatalf("GetUserList call %d failed: %v", i+1, err)
		}
		if len(users) != 1 {
			t.Fatalf("users count = %d, want 1", len(users))
		}
	}
}

func TestClient_GetUserList_ParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	_, err := client.GetUserList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
		t.Fatalf("expected parse APIError, got %T: %v", err, err)
	}
}

func TestClient_GetUserList_ParseErrorDoesNotCommitCache(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("ETag", "bad-etag")
			_, _ = w.Write([]byte(`not valid json`))
			return
		}
		w.Header().Set("ETag", "good-etag")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	if _, err := client.GetUserList(context.Background()); err == nil {
		t.Fatal("expected parse error")
	}
	users, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("second GetUserList failed: %v", err)
	}
	if len(users) != 1 || users[0].Uuid != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("users = %#v", users)
	}
	if client.userEtag != "good-etag" {
		t.Fatalf("userEtag = %q, want good-etag", client.userEtag)
	}
}

func TestClient_GetUserList_304WithoutCacheReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	users, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("GetUserList failed: %v", err)
	}
	if users != nil {
		t.Fatalf("users = %#v, want nil", users)
	}
}

func TestClient_GetRequestsUseConstructionSnapshot(t *testing.T) {
	requestCount := 0
	var requestErrors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if got := r.URL.Query().Get("token"); got != "token" {
			requestErrors = append(requestErrors, fmt.Sprintf("token query = %q", got))
		}
		if got := r.URL.Query().Get("node_id"); got != "7" {
			requestErrors = append(requestErrors, fmt.Sprintf("node_id query = %q", got))
		}
		if got := r.URL.Query().Get("node_type"); got != "vless" {
			requestErrors = append(requestErrors, fmt.Sprintf("node_type query = %q", got))
		}
		if requestCount == 1 && r.Header.Get(headerIfNoneMatch) != "" {
			requestErrors = append(requestErrors, fmt.Sprintf("first If-None-Match = %q", r.Header.Get(headerIfNoneMatch)))
		}
		if requestCount == 2 && r.Header.Get(headerIfNoneMatch) != "etag-1" {
			requestErrors = append(requestErrors, fmt.Sprintf("second If-None-Match = %q", r.Header.Get(headerIfNoneMatch)))
		}
		w.Header().Set(headerETag, "etag-1")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()

	client := New(&Config{APIHost: server.URL, Key: "token", NodeID: 7, NodeType: "vless", Timeout: 1})
	client.Token = "mutated-token"
	client.NodeId = 99
	client.NodeType = "vmess"
	client.APIHost = "http://127.0.0.1:1"

	if _, err := client.GetUserList(context.Background()); err != nil {
		t.Fatalf("first GetUserList failed: %v", err)
	}
	if _, err := client.GetUserList(context.Background()); err != nil {
		t.Fatalf("second GetUserList failed: %v", err)
	}
	if len(requestErrors) > 0 {
		t.Fatalf("request errors: %s", strings.Join(requestErrors, "; "))
	}
}

func TestClient_CachedUserListDoesNotWaitForUserFetch(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	closeRelease := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`))
	}))
	defer server.Close()
	defer closeRelease()

	client := newTestClient(t, server.URL, "vless")
	client.userList = &UserListBody{Users: []UserInfo{{Id: 1, Uuid: "cached"}}}

	fetchDone := make(chan error, 1)
	go func() {
		_, err := client.GetUserList(context.Background())
		fetchDone <- err
	}()
	<-started

	cacheDone := make(chan []UserInfo, 1)
	go func() {
		cacheDone <- client.CachedUserList()
	}()

	select {
	case users := <-cacheDone:
		if len(users) != 1 || users[0].Uuid != "cached" {
			t.Fatalf("cached users = %#v", users)
		}
		closeRelease()
	case <-time.After(50 * time.Millisecond):
		t.Fatal("CachedUserList waited for in-flight GetUserList network request")
	}

	select {
	case err := <-fetchDone:
		if err != nil {
			t.Fatalf("GetUserList failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GetUserList did not finish after release")
	}
}
