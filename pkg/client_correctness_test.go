package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
)

func TestTlsSettingsXverForms(t *testing.T) {
	for _, value := range []string{"0", "1", "2", `"0"`, `"1"`, `"2"`, "null", ""} {
		t.Run("valid/"+value, func(t *testing.T) {
			body := `{"server_name":"example.com","private_key":"fixture-key"`
			if value != "" {
				body += `,"xver":` + value
			}
			body += "}"
			settings := TlsSettings{Xver: 2}
			if err := json.Unmarshal([]byte(body), &settings); err != nil {
				t.Fatal(err)
			}
			var want uint64
			switch value {
			case "1", `"1"`:
				want = 1
			case "2", `"2"`:
				want = 2
			}
			if settings.Xver != want || settings.ServerName != "example.com" || settings.PrivateKey != "fixture-key" {
				t.Fatal("decoded settings do not match")
			}
			encoded, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip TlsSettings
			if err := json.Unmarshal(encoded, &roundtrip); err != nil || roundtrip != settings {
				t.Fatal("roundtrip failed")
			}
		})
	}
	for _, value := range []string{"3", "-1", "1.5", "true", "{}", "[]", `""`, `"null"`, `"bad"`, `"3"`, "18446744073709551616"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			settings := TlsSettings{Xver: 1, ServerName: "unchanged"}
			before := settings
			if err := json.Unmarshal([]byte(`{"xver":`+value+`}`), &settings); err == nil {
				t.Fatal("expected error")
			}
			if settings != before {
				t.Fatal("failed decode modified settings")
			}
		})
	}
}

func TestClientHysteriaVersionContract(t *testing.T) {
	for _, protocol := range []string{Hysteria, Hysteria2} {
		for _, version := range []string{"", "null", "0", "1", "2", "3"} {
			t.Run(protocol+"/"+version, func(t *testing.T) {
				body := `{"server_port":443`
				if version != "" {
					body += `,"version":` + version
				}
				body += "}"
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(headerETag, `"new"`)
					_, _ = w.Write([]byte(body))
				}))
				defer server.Close()
				client := newTestClient(t, server.URL, protocol)
				node, err := client.GetNodeInfo(context.Background())
				valid := protocol == Hysteria && version == "1" || protocol == Hysteria2 && version == "2"
				if valid {
					if err != nil || node == nil {
						t.Fatalf("expected config, got %v", err)
					}
					return
				}
				var apiErr *APIError
				if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
					t.Fatalf("expected parse error, got %v", err)
				}
				if client.nodeEtag != "" || client.responseBodyHash != "" {
					t.Fatal("invalid config changed cache validators")
				}
			})
		}
	}
}

func TestClientOnlineNormalizationAndClear(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != apiAlivePath || r.Method != http.MethodPost {
			t.Error("unexpected endpoint")
		}
		var body map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		nodeID := r.URL.Query().Get("node_id")
		want := map[int][]string{1: {"203.0.113.1_" + nodeID, "2001:db8::1_" + nodeID}, 2: {}, 3: {}, 4: {"203.0.113.1_" + nodeID}}
		if !reflect.DeepEqual(body, want) {
			t.Errorf("unexpected payload: %s", fmt.Sprint(body))
		}
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, Vless)
	data := map[int][]netip.Addr{
		1: {netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("::ffff:203.0.113.1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::1")},
		2: {}, 3: nil, 4: {netip.MustParseAddr("203.0.113.1")},
	}
	if err := client.ReportNodeOnlineUsers(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	if len(data[1]) != 4 || !data[1][1].Is4In6() {
		t.Fatal("input mutated")
	}
}
