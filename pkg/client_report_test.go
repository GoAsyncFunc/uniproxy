package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestClient_ReportAcknowledgements(t *testing.T) {
	reports := []struct {
		name string
		call func(*Client) error
	}{
		{name: "traffic", call: func(client *Client) error {
			return client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}})
		}},
		{name: "online", call: func(client *Client) error {
			return client.ReportNodeOnlineUsers(context.Background(), map[int][]netip.Addr{1: {netip.MustParseAddr("203.0.113.1")}})
		}},
	}
	responses := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{name: "panel success", status: http.StatusOK, body: `{"data":true}`},
		{name: "legacy no content", status: http.StatusNoContent},
		{name: "negative acknowledgement", status: http.StatusOK, body: `{"data":false}`, wantErr: true},
		{name: "missing acknowledgement", status: http.StatusOK, body: `{}`, wantErr: true},
		{name: "null acknowledgement", status: http.StatusOK, body: `{"data":null}`, wantErr: true},
		{name: "string acknowledgement", status: http.StatusOK, body: `{"data":"true"}`, wantErr: true},
		{name: "null response", status: http.StatusOK, body: `null`, wantErr: true},
		{name: "empty response", status: http.StatusOK, wantErr: true},
		{name: "login page", status: http.StatusOK, body: `<html>Please sign in</html>`, wantErr: true},
		{name: "redirect without location", status: http.StatusFound, wantErr: true},
		{name: "not modified", status: http.StatusNotModified, wantErr: true},
		{name: "server error", status: http.StatusInternalServerError, body: `{"message":"token is error"}`, wantErr: true},
	}
	for _, report := range reports {
		for _, response := range responses {
			t.Run(report.name+"/"+response.name, func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					calls.Add(1)
					writer.WriteHeader(response.status)
					_, _ = writer.Write([]byte(response.body))
				}))
				defer server.Close()
				err := report.call(newTestClient(t, server.URL, "vless"))
				if (err != nil) != response.wantErr {
					t.Fatalf("error = %v, want error = %t", err, response.wantErr)
				}
				if calls.Load() != 1 {
					t.Fatalf("requests = %d, want one report attempt", calls.Load())
				}
			})
		}
	}
}

func TestClient_RejectsRedirectsWithoutFollowing(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(fmt.Sprintf("%s/%d", method, status), func(t *testing.T) {
				var redirected atomic.Int32
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					calls.Add(1)
					if request.URL.Path == "/login" {
						redirected.Add(1)
						_, _ = writer.Write([]byte(`{"data":true}`))
						return
					}
					writer.Header().Set("Location", "/login")
					writer.WriteHeader(status)
				}))
				defer server.Close()
				client := newTestClient(t, server.URL, "vless")
				var err error
				if method == http.MethodGet {
					_, err = client.GetUserList(context.Background())
				} else {
					err = client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}})
				}
				var apiError *APIError
				if !errors.As(err, &apiError) || apiError.StatusCode != status {
					t.Fatalf("error = %v, want HTTP %d error", err, status)
				}
				if redirected.Load() != 0 || calls.Load() != 1 {
					t.Fatalf("requests = %d, redirects = %d, want one request and no redirects", calls.Load(), redirected.Load())
				}
			})
		}
	}
}

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

	err := client.ReportNodeOnlineUsers(context.Background(), map[int][]netip.Addr{
		1: {netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
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

func TestBuildOnlinePayload_FormatsWithNodeID(t *testing.T) {
	data := map[int][]netip.Addr{
		1: {netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
	}
	got := buildOnlinePayload(data, 7)
	if len(got[1]) != 2 || got[1][0] != "203.0.113.1_7" || got[1][1] != "203.0.113.2_7" {
		t.Fatalf("got[1] = %#v", got[1])
	}
}

func TestClient_ReportNodeOnlineUsers_RejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name string
		data map[int][]netip.Addr
	}{
		{name: "zero uid", data: map[int][]netip.Addr{0: {netip.MustParseAddr("203.0.113.1")}}},
		{name: "negative uid", data: map[int][]netip.Addr{-1: {netip.MustParseAddr("203.0.113.1")}}},
		{name: "zoned ip", data: map[int][]netip.Addr{1: {netip.MustParseAddr("fe80::1%eth0")}}},
		{name: "invalid ip", data: map[int][]netip.Addr{1: {netip.Addr{}}}},
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
	if err := client.ReportNodeOnlineUsers(context.Background(), map[int][]netip.Addr{}); err != nil {
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
