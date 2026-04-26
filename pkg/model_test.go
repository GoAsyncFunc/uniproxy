package pkg

import (
	"reflect"
	"testing"
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
	domains, protocols := SplitBlockRouteMatches([]string{"regexp:ads.example.com", "protocol:bittorrent", " protocol:quic ", "domain:example.com"})
	if !reflect.DeepEqual(domains, []string{"regexp:ads.example.com", "domain:example.com"}) {
		t.Fatalf("domains = %#v", domains)
	}
	if !reflect.DeepEqual(protocols, []string{"bittorrent", "quic"}) {
		t.Fatalf("protocols = %#v", protocols)
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
