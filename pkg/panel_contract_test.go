package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Exercise each fixture through the complete client, not just its handler.
// These are local contract tests, not evidence of live-panel compatibility.
func TestPanelFixtureHTTPTransitions(t *testing.T) {
	for _, fixture := range loadPanelFixtures(t) {
		if fixture.Protocol == "common" {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			var updated map[string]json.RawMessage
			if err := json.Unmarshal(fixture.Body, &updated); err != nil {
				t.Fatal(err)
			}
			var oldPort int
			if err := json.Unmarshal(updated["server_port"], &oldPort); err != nil {
				t.Fatal(err)
			}
			newPort := oldPort%65535 + 1
			updated["server_port"] = json.RawMessage(strconv.Itoa(newPort))
			newBody, err := json.Marshal(updated)
			if err != nil {
				t.Fatal(err)
			}
			steps := []struct {
				status                  int
				etag, body, requestETag string
			}{
				{200, `"a"`, string(fixture.Body), ""},
				{304, `"b"`, "", `"a"`},
				{200, `"invalid"`, `{"server_port":0}`, `"b"`},
				{304, "", "", `"b"`},
				{200, `"c"`, string(newBody), `"b"`},
				{304, "", "", `"c"`},
			}
			index := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if index >= len(steps) {
					t.Error("unexpected extra request")
					w.WriteHeader(400)
					return
				}
				step := steps[index]
				index++
				if r.Method != http.MethodGet || r.URL.Path != apiConfigPath {
					t.Error("unexpected endpoint")
				}
				if r.URL.Query().Get("node_type") != fixture.Protocol || r.URL.Query().Get("node_id") != "1" || r.URL.Query().Get("token") != "fixture-token" {
					t.Error("incorrect query parameters")
				}
				if r.Header.Get(headerIfNoneMatch) != step.requestETag {
					t.Errorf("step %d: wrong request validator", index)
				}
				if step.etag != "" {
					w.Header().Set(headerETag, step.etag)
				}
				w.Header().Set("Content-Type", contentTypeJSON)
				w.WriteHeader(step.status)
				_, _ = w.Write([]byte(step.body))
			}))
			defer server.Close()
			client, err := NewWithError(&Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: fixture.Protocol, Timeout: 5})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			var originalHash string
			for i := range steps {
				node, err := client.GetNodeInfo(context.Background())
				switch i {
				case 0:
					if err != nil || node == nil {
						t.Fatalf("initial config: %v", err)
					}
					assertParsedFixture(t, fixture, node, node.Common)
					originalHash = client.responseBodyHash
				case 2:
					var apiErr *APIError
					if node != nil || !errors.As(err, &apiErr) || !apiErr.IsParseError() {
						t.Fatalf("invalid response: %v", err)
					}
					if client.responseBodyHash != originalHash || client.nodeEtag != `"b"` {
						t.Fatal("invalid response polluted validators")
					}
				case 4:
					if err != nil || node == nil || node.Common.ServerPort != newPort {
						t.Fatalf("updated config: %v", err)
					}
					if client.responseBodyHash == originalHash {
						t.Fatal("new body hash not stored")
					}
				default:
					if err != nil || node != nil {
						t.Fatalf("step %d expected unchanged config: %v", i, err)
					}
				}
			}
			if index != len(steps) {
				t.Fatalf("requests=%d want=%d", index, len(steps))
			}
		})
	}
}
