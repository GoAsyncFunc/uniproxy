package pkg

import (
	"reflect"
	"testing"
	"time"
)

func TestRouteActionClassification(t *testing.T) {
	if !IsBlockRouteAction(RouteActionBlock) || !IsBlockRouteAction(RouteActionBlockIP) || !IsBlockRouteAction(RouteActionBlockPort) || !IsBlockRouteAction(RouteActionProtocol) {
		t.Fatal("expected block actions to be classified as block routes")
	}
	if IsBlockRouteAction(RouteActionDNS) {
		t.Fatal("dns should not be classified as block route")
	}
	if !IsCustomRouteAction(RouteActionRoute) || !IsCustomRouteAction(RouteActionRouteIP) {
		t.Fatal("expected route actions to be classified as custom routes")
	}
	if IsCustomRouteAction(RouteActionDefaultOut) {
		t.Fatal("default_out should not be classified as custom route")
	}
	if !IsDefaultOutboundRouteAction(RouteActionDefaultOut) {
		t.Fatal("expected default_out to be classified as default outbound route")
	}
}

func TestNormalizeRouteMatch(t *testing.T) {
	tests := []struct {
		name  string
		match interface{}
		want  []string
	}{
		{
			name:  "comma string",
			match: "regexp:example.com, protocol:bittorrent, ",
			want:  []string{"regexp:example.com", "protocol:bittorrent"},
		},
		{
			name:  "string slice",
			match: []string{"domain:example.com", "", " geosite:cn "},
			want:  []string{"domain:example.com", "geosite:cn"},
		},
		{
			name:  "interface slice",
			match: []interface{}{"1.1.1.1", 123, " 8.8.8.8 "},
			want:  []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:  "unsupported nil",
			match: nil,
			want:  []string{},
		},
		{
			name:  "unsupported number",
			match: 123,
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeRouteMatch(tt.match)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("NormalizeRouteMatch() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSplitBlockRouteMatches(t *testing.T) {
	tests := []struct {
		name          string
		matches       []string
		wantDomains   []string
		wantProtocols []string
	}{
		{name: "nil", matches: nil, wantDomains: []string{}, wantProtocols: []string{}},
		{name: "empty values", matches: []string{"", "   "}, wantDomains: []string{}, wantProtocols: []string{}},
		{name: "mixed domains and protocols", matches: []string{"regexp:ads.example.com", "protocol:bittorrent", " protocol:quic ", "domain:example.com"}, wantDomains: []string{"regexp:ads.example.com", "domain:example.com"}, wantProtocols: []string{"bittorrent", "quic"}},
		{name: "empty protocol value is ignored", matches: []string{"protocol:", "domain:example.com"}, wantDomains: []string{"domain:example.com"}, wantProtocols: []string{}},
		{name: "duplicate protocols are preserved", matches: []string{"protocol:quic", "protocol:quic"}, wantDomains: []string{}, wantProtocols: []string{"quic", "quic"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domains, protocols := SplitBlockRouteMatches(tt.matches)
			if !reflect.DeepEqual(domains, tt.wantDomains) {
				t.Fatalf("domains = %#v, want %#v", domains, tt.wantDomains)
			}
			if !reflect.DeepEqual(protocols, tt.wantProtocols) {
				t.Fatalf("protocols = %#v, want %#v", protocols, tt.wantProtocols)
			}
		})
	}
}

func TestIntervalToTime(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want time.Duration
	}{
		{name: "int", in: 60, want: 60 * time.Second},
		{name: "string", in: "45", want: 45 * time.Second},
		{name: "bad string", in: "bad", want: 0},
		{name: "float", in: float64(2.5), want: 2 * time.Second},
		{name: "negative int", in: -1, want: 0},
		{name: "negative string", in: "-10", want: 0},
		{name: "negative float", in: float64(-2.5), want: 0},
		{name: "string with whitespace", in: " 30 ", want: 30 * time.Second},
		{name: "nil", in: nil, want: 0},
		{name: "bool", in: true, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IntervalToTime(tt.in); got != tt.want {
				t.Fatalf("IntervalToTime(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestProcessCommonNodePreservesRoutesAndLegacyRules(t *testing.T) {
	node := &NodeInfo{RawDNS: RawDNS{DNSMap: map[string]map[string]interface{}{}}}
	common := &CommonNode{
		Routes: []Route{
			{Id: 1, Match: "regexp:ads.example.com,protocol:bittorrent", Action: RouteActionBlock},
			{Id: 2, Match: []string{"1.1.1.1", "8.8.8.8"}, Action: RouteActionBlockIP},
			{Id: 3, Match: []string{"53", "1000-2000"}, Action: RouteActionBlockPort},
			{Id: 4, Match: []string{"quic"}, Action: RouteActionProtocol},
			{Id: 5, Match: []string{"domain:example.com"}, Action: RouteActionDNS, ActionValue: "1.1.1.1"},
			{Id: 6, Match: []string{"domain:route.example.com"}, Action: RouteActionRoute, ActionValue: `{"tag":"proxy","protocol":"freedom"}`},
			{Id: 7, Match: []string{"10.0.0.0/8"}, Action: RouteActionRouteIP, ActionValue: `{"tag":"ip-proxy","protocol":"freedom"}`},
			{Id: 8, Action: RouteActionDefaultOut, ActionValue: `{"tag":"direct","protocol":"freedom"}`},
		},
	}

	node.ProcessCommonNode(common)

	if len(node.Routes) != 8 {
		t.Fatalf("routes count = %d, want 8", len(node.Routes))
	}
	if len(common.Routes) != 0 {
		t.Fatalf("common routes count = %d, want 0", len(common.Routes))
	}
	if node.Routes[5].Action != RouteActionRoute || node.Routes[5].ActionValue == "" {
		t.Fatalf("custom route not preserved: %#v", node.Routes[5])
	}
	if node.Routes[7].Action != RouteActionDefaultOut || node.Routes[7].ActionValue == "" {
		t.Fatalf("default outbound route not preserved: %#v", node.Routes[7])
	}
	if !reflect.DeepEqual(node.Rules.Regexp, []string{"ads.example.com"}) {
		t.Fatalf("rules regexp = %#v", node.Rules.Regexp)
	}
	if !reflect.DeepEqual(node.Rules.Protocol, []string{"bittorrent"}) {
		t.Fatalf("rules protocol = %#v", node.Rules.Protocol)
	}
	gotDNS := node.RawDNS.DNSMap["4"]
	if gotDNS["address"] != "1.1.1.1" {
		t.Fatalf("dns address = %#v", gotDNS["address"])
	}
	if !reflect.DeepEqual(gotDNS["domains"], []string{"domain:example.com"}) {
		t.Fatalf("dns domains = %#v", gotDNS["domains"])
	}
}

func TestProcessCommonNode_DNSRouteInitializesNilDNSMap(t *testing.T) {
	node := &NodeInfo{}
	common := &CommonNode{
		Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: "1.1.1.1"}},
	}

	node.ProcessCommonNode(common)

	gotDNS := node.RawDNS.DNSMap["0"]
	if gotDNS["address"] != "1.1.1.1" {
		t.Fatalf("dns address = %#v", gotDNS["address"])
	}
}

func TestProcessCommonNode_BaseConfigAndDNSMain(t *testing.T) {
	node := &NodeInfo{RawDNS: RawDNS{DNSMap: map[string]map[string]interface{}{}, DNSJson: []byte{}}}
	common := &CommonNode{
		ServerPort: 1234,
		BaseConfig: &BaseConfig{PushInterval: "30", PullInterval: float64(45)},
		Routes:     []Route{{Action: RouteActionDNS, Match: []string{"main", `{"servers":["1.1.1.1"]}`}}},
	}

	node.ProcessCommonNode(common)

	if node.PushInterval != 30*time.Second {
		t.Fatalf("PushInterval = %v, want 30s", node.PushInterval)
	}
	if node.PullInterval != 45*time.Second {
		t.Fatalf("PullInterval = %v, want 45s", node.PullInterval)
	}
	if string(node.RawDNS.DNSJson) != `{"servers":["1.1.1.1"]}` {
		t.Fatalf("DNSJson = %q", string(node.RawDNS.DNSJson))
	}
	if common.BaseConfig != nil {
		t.Fatal("common BaseConfig was not cleared")
	}
}

func TestProcessCommonNode_NilDoesNotMutateNode(t *testing.T) {
	node := &NodeInfo{PushInterval: time.Second, Routes: []Route{{Action: RouteActionBlock}}}
	node.ProcessCommonNode(nil)
	if node.PushInterval != time.Second {
		t.Fatalf("PushInterval = %v, want 1s", node.PushInterval)
	}
	if len(node.Routes) != 1 {
		t.Fatalf("routes length = %d, want 1", len(node.Routes))
	}
}
