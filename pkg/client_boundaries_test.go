package pkg

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestCacheValidatorTransitions(t *testing.T) {
	for _, kind := range []string{"node", "users"} {
		t.Run(kind, func(t *testing.T) {
			initial, changed := `{"server_port":443}`, `{"server_port":444}`
			if kind == "users" {
				initial = `{"users":[]}`
				changed = `{"users":[{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}]}`
			}
			steps := []struct {
				status                 int
				etag, body, wantHeader string
				wantErr                bool
			}{
				{304, `"unsolicited"`, "", "", true},
				{200, `"a"`, initial, "", false},
				{304, `"b"`, "", `"a"`, false},
				{304, "", "", `"b"`, false},
				{200, `"bad"`, `{`, `"b"`, true},
				{200, "", changed, `"b"`, false},
				{304, `"unsolicited"`, "", "", true},
				{200, `"c"`, changed, "", false},
				{304, "", "", `"c"`, false},
			}
			index := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if index >= len(steps) {
					t.Error("unexpected request")
					w.WriteHeader(400)
					return
				}
				s := steps[index]
				index++
				if got := r.Header.Get(headerIfNoneMatch); got != s.wantHeader {
					t.Errorf("step %d header = %q, want %q", index, got, s.wantHeader)
				}
				if s.etag != "" {
					w.Header().Set(headerETag, s.etag)
				}
				w.WriteHeader(s.status)
				_, _ = w.Write([]byte(s.body))
			}))
			defer server.Close()
			client := newTestClient(t, server.URL, Vless)
			for i, s := range steps {
				var err error
				if kind == "node" {
					_, err = client.GetNodeInfo(context.Background())
				} else {
					_, err = client.GetUserList(context.Background())
				}
				if s.wantErr {
					var apiErr *APIError
					if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
						t.Fatalf("step %d expected parse error, got %v", i, err)
					}
				} else if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
			}
			if index != len(steps) {
				t.Fatalf("requests = %d", index)
			}
			if kind == "users" && len(client.CachedUserList()) != 1 {
				t.Fatal("lost cached users")
			}
		})
	}
}

func TestIntervalBoundaries(t *testing.T) {
	for _, value := range []any{strconv.FormatInt(maxDurationSeconds+1, 10), float64(maxDurationSeconds + 1), math.NaN(), math.Inf(1), math.Inf(-1), math.MaxFloat64} {
		if got := IntervalToTime(value); got != 0 {
			t.Fatalf("invalid interval returned %v", got)
		}
	}
	if strconv.IntSize == 64 {
		if got := IntervalToTime(strconv.FormatInt(maxDurationSeconds, 10)); got != time.Duration(maxDurationSeconds)*time.Second {
			t.Fatalf("max interval = %v", got)
		}
		value := maxDurationSeconds + 1
		if IntervalToTime(int(value)) != 0 {
			t.Fatal("integer overflow not rejected")
		}
	}
}

func TestClientIntervalConfigBoundaries(t *testing.T) {
	for _, value := range []string{"0", "-1", `"bad"`, `""`, "true", "{}", "[]", "0.5", "9223372037", "1e100"} {
		for _, field := range []string{"push_interval", "pull_interval"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				body := `{"server_port":443,"base_config":{"` + field + `":` + value + `}}`
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(headerETag, `"bad"`)
					_, _ = w.Write([]byte(body))
				}))
				defer server.Close()
				client := newTestClient(t, server.URL, Vless)
				_, err := client.GetNodeInfo(context.Background())
				var apiErr *APIError
				if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
					t.Fatalf("expected parse error, got %v", err)
				}
				if client.nodeEtag != "" || client.responseBodyHash != "" {
					t.Fatal("invalid interval polluted cache")
				}
			})
		}
	}
	for _, base := range []string{"", `,"base_config":null`, `,"base_config":{}`, `,"base_config":{"push_interval":null,"pull_interval":null}`, `,"base_config":{"push_interval":"60","pull_interval":60}`} {
		t.Run("defaults/"+base, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"server_port":443` + base + `}`))
			}))
			defer server.Close()
			node, err := newTestClient(t, server.URL, Vless).GetNodeInfo(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if node.PushInterval != time.Minute || node.PullInterval != time.Minute {
				t.Fatal("expected 60s intervals")
			}
		})
	}
}

func TestTimeoutBoundaries(t *testing.T) {
	for _, seconds := range []int{-1, 0, 1} {
		client, err := NewWithError(&Config{APIHost: "http://localhost", Key: "token", NodeID: 1, NodeType: Vless, Timeout: seconds})
		if err != nil {
			t.Fatal(err)
		}
		want := 5 * time.Second
		if seconds > 0 {
			want = time.Second
		}
		if got := client.client.GetClient().Timeout; got != want {
			t.Fatalf("timeout = %v, want %v", got, want)
		}
	}
	if strconv.IntSize == 64 {
		value := maxDurationSeconds + 1
		_, err := NewWithError(&Config{APIHost: "http://localhost", Key: "token", NodeID: 1, NodeType: Vless, Timeout: int(value)})
		if err == nil {
			t.Fatal("expected timeout overflow error")
		}
	}
}
