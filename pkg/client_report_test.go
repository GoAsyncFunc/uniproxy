package pkg

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ReportNodeOnlineUsers_PostsAlivePayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != apiAlivePath {
			t.Fatalf("path = %q, want %q", r.URL.Path, apiAlivePath)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != contentTypeJSON {
			t.Fatalf("Content-Type = %q, want %q", got, contentTypeJSON)
		}
		if got := r.URL.Query().Get("token"); got != "test-token" {
			t.Fatalf("token query = %q", got)
		}

		var body map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		ips := body[1]
		if len(ips) != 2 || ips[0] != "203.0.113.1_1" || ips[1] != "203.0.113.2_1" {
			t.Fatalf("body[1] = %#v", ips)
		}
		_, _ = w.Write([]byte(`{"data": true}`))
	}))
	defer server.Close()

	client := New(&Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "vless",
		Timeout:  1,
	})

	err := client.ReportNodeOnlineUsers(context.Background(), map[int][]string{
		1: {"203.0.113.1_1", "203.0.113.2_1"},
	})
	if err != nil {
		t.Fatalf("ReportNodeOnlineUsers failed: %v", err)
	}
}

func TestClient_ReportUserTraffic_RejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name    string
		traffic []UserTraffic
	}{
		{name: "zero uid", traffic: []UserTraffic{{UID: 0, Upload: 1, Download: 1}}},
		{name: "negative uid", traffic: []UserTraffic{{UID: -1, Upload: 1, Download: 1}}},
		{name: "negative upload", traffic: []UserTraffic{{UID: 1, Upload: -1, Download: 1}}},
		{name: "negative download", traffic: []UserTraffic{{UID: 1, Upload: 1, Download: -1}}},
		{name: "duplicate uid", traffic: []UserTraffic{{UID: 1, Upload: 1, Download: 1}, {UID: 1, Upload: 2, Download: 2}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			err := client.ReportUserTraffic(context.Background(), tt.traffic)
			if err == nil {
				t.Fatal("expected error")
			}
			if called {
				t.Fatal("server was called for invalid payload")
			}
		})
	}
}

func TestClient_ReportUserTraffic_EmptyPayloadIsNoop(t *testing.T) {
	tests := []struct {
		name    string
		traffic []UserTraffic
	}{
		{name: "nil traffic", traffic: nil},
		{name: "empty traffic", traffic: []UserTraffic{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			if err := client.ReportUserTraffic(context.Background(), tt.traffic); err != nil {
				t.Fatalf("ReportUserTraffic failed: %v", err)
			}
			if called {
				t.Fatal("server was called for empty traffic")
			}
		})
	}
}

func TestCloneOnlineUsers_DoesNotShareCallerMapOrSlices(t *testing.T) {
	data := map[int][]string{1: {"203.0.113.1_1"}}

	cloned := cloneOnlineUsers(data)
	data[1][0] = "not-ip_1"
	data[2] = []string{"203.0.113.2_1"}

	if got := cloned[1]; len(got) != 1 || got[0] != "203.0.113.1_1" {
		t.Fatalf("cloned[1] = %#v", got)
	}
	if _, ok := cloned[2]; ok {
		t.Fatalf("cloned contains later caller map mutation: %#v", cloned)
	}
}

func TestClient_ReportNodeOnlineUsers_RejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name string
		data map[int][]string
	}{
		{name: "zero uid", data: map[int][]string{0: {"203.0.113.1_1"}}},
		{name: "negative uid", data: map[int][]string{-1: {"203.0.113.1_1"}}},
		{name: "empty users", data: map[int][]string{1: {}}},
		{name: "empty user entry", data: map[int][]string{1: {""}}},
		{name: "invalid ip", data: map[int][]string{1: {"not-ip_1"}}},
		{name: "empty suffix", data: map[int][]string{1: {"203.0.113.1_"}}},
		{name: "empty ip", data: map[int][]string{1: {"_1"}}},
		{name: "multiple separators", data: map[int][]string{1: {"203.0.113.1_1_2"}}},
		{name: "non-numeric suffix", data: map[int][]string{1: {"203.0.113.1_bad"}}},
		{name: "blank suffix", data: map[int][]string{1: {"203.0.113.1_  "}}},
		{name: "leading space in ip", data: map[int][]string{1: {" 203.0.113.1_1"}}},
		{name: "leading space in suffix", data: map[int][]string{1: {"203.0.113.1_ 1"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "vless")
			err := client.ReportNodeOnlineUsers(context.Background(), tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if called {
				t.Fatal("server was called for invalid payload")
			}
		})
	}
}

func TestClient_ReportNodeOnlineUsers_EmptyMapSkipsRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	if err := client.ReportNodeOnlineUsers(context.Background(), map[int][]string{}); err != nil {
		t.Fatalf("ReportNodeOnlineUsers failed: %v", err)
	}
	if called {
		t.Fatal("server should not be called for empty online users")
	}
}

func TestClient_ReportUserTraffic_PostsPushPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != apiPushPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, apiPushPath)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		if got := r.URL.Query().Get("token"); got != "token" {
			t.Fatalf("token query = %q", got)
		}
		var body map[int][]int64
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		got := body[1]
		if len(got) != 2 || got[0] != 10 || got[1] != 20 {
			t.Fatalf("body[1] = %#v", got)
		}
		_, _ = w.Write([]byte(`{"data": true}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "vless")
	err := client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}})
	if err != nil {
		t.Fatalf("ReportUserTraffic failed: %v", err)
	}
}
