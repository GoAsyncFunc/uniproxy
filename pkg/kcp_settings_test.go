package pkg

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestKCPSettings(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", "{}", `{"header":null,"seed":null,"mtu":null}`} {
		got, err := ParseNetworkSettings("kcp", json.RawMessage(raw))
		if err != nil || !reflect.DeepEqual(got.KCP, KCPSettings{}) {
			t.Fatal("empty/null fields must remain unset")
		}
	}
	got := parseNetwork(t, "kcp", `{"header":{"type":"dtls","unused":true},"seed":"","mtu":0,"tti":50,"uplinkCapacity":5,"downlinkCapacity":20,"cwndMultiplier":1,"maxSendingWindow":2097152,"extra":{}}`)
	if got.KCP.Header == nil || got.KCP.Header.Type != "dtls" || got.KCP.Seed == nil || *got.KCP.Seed != "" || got.KCP.MTU == nil || *got.KCP.MTU != 0 {
		t.Fatal("explicit empty and zero values lost")
	}
	if !reflect.DeepEqual(got.UnknownKeys, []string{"extra", "header.unused"}) {
		t.Fatal("unknown dotted keys must be sorted")
	}
	if *got.KCP.TTI != 50 || *got.KCP.UplinkCapacity != 5 || *got.KCP.DownlinkCapacity != 20 || *got.KCP.CWNDMultiplier != 1 || *got.KCP.MaxSendingWindow != 2097152 {
		t.Fatal("numeric fields lost")
	}
	// No transport policy: preserving an unknown header or a negative numeric
	// value lets the consuming node make an explicit admission decision.
	got = parseNetwork(t, "kcp", `{"header":{"type":"future"},"seed":"synthetic-seed","tti":-1}`)
	if got.KCP.Header.Type != "future" || *got.KCP.TTI != -1 {
		t.Fatal("SDK applied transport policy")
	}
	for _, raw := range []string{`{"seed":123}`, `{"seed":[]}`, `{"header":3}`, `{"header":{"type":false}}`, `{"mtu":"1350"}`, `{"tti":0.5}`, `{"cwndMultiplier":{}}`, `{"uplinkCapacity":true}`, `{"downlinkCapacity":[]}`, `{"maxSendingWindow":9223372036854775808}`} {
		_, err := ParseNetworkSettings("kcp", json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "synthetic-seed") {
			t.Fatal("invalid types must fail with a static diagnostic")
		}
	}
}
