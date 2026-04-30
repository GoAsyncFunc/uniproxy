package pkg

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestSensitiveModelFormattingRedactsSecrets(t *testing.T) {
	route := Route{Id: 1, Match: `main,{"client_secret":"match-secret"}`, Action: "action-secret", ActionValue: `{"token":"route-secret"}`}
	dnsRoute := Route{Id: 2, Match: `main,{"resolver":"route-dns-secret.example.com"}`, Action: RouteActionDNS, ActionValue: `{"token":"dns-action-secret"}`}
	rawDNS := RawDNS{DNSJson: []byte(`{"resolver":"internal-dns-secret.example.com","client_secret":"dns-secret"}`)}
	tlsSettings := TlsSettings{ServerName: "tls-sni-secret.example.com", Dest: "dest-secret.example.com", ServerPort: "443", ShortId: "short-id-secret", PrivateKey: "private-secret", Mldsa65Seed: "seed-secret", Xver: 1}
	encSettings := EncSettings{Mode: "native-secret-mode", Ticket: "enc-ticket-secret", ServerPadding: "server-padding-secret", PrivateKey: "enc-private-secret"}
	common := &CommonNode{Host: "common-host-secret.example.com", ServerPort: 443, ServerName: "common-sni-secret.example.com", Routes: []Route{route, dnsRoute}, BaseConfig: &BaseConfig{PushInterval: "push-secret", PullInterval: "pull-secret"}}
	vmess := &VMessNode{CommonNode: *common, TlsSettings: tlsSettings, Network: "network-secret", NetworkSettings: []byte(`{"host":"network-secret.example.com"}`), Encryption: "encryption-secret", EncryptionSettings: encSettings}
	vless := &VlessNode{CommonNode: *common, TlsSettings: tlsSettings, Network: "network-secret", NetworkSettings: []byte(`{"host":"network-secret.example.com"}`), Encryption: "encryption-secret", EncryptionSettings: encSettings, Flow: "flow-secret"}
	shadowsocks := &ShadowsocksNode{CommonNode: *common, Cipher: "cipher-secret", ServerKey: "server-key-secret", Obfs: "obfs-type-secret", ObfsSettings: []byte(`{"password":"obfs-secret"}`)}
	trojan := &TrojanNode{CommonNode: *common, Network: "network-secret", NetworkSettings: []byte(`{"host":"trojan-network-secret.example.com"}`)}
	tuic := &TuicNode{CommonNode: *common, CongestionControl: "congestion-secret", ZeroRTTHandshake: true}
	anyTLS := &AnyTlsNode{CommonNode: *common, PaddingScheme: []string{"padding-secret"}}
	hysteria := &HysteriaNode{CommonNode: *common, Obfs: "hysteria-obfs-secret"}
	hysteria2 := &Hysteria2Node{CommonNode: *common, ObfsType: "obfs-type-secret", ObfsPassword: "obfs-password-secret"}
	onlineUser := OnlineUser{UID: 42, IP: "203.0.113.10"}
	rules := Rules{Regexp: []string{"rules-regexp-secret.example.com"}, Protocol: []string{"rules-protocol-secret"}}
	user := UserInfo{Id: 1, Uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	node := &NodeInfo{
		Id:           7,
		Type:         Vless,
		Security:     Reality,
		RawDNS:       rawDNS,
		Routes:       []Route{route, dnsRoute},
		VMess:        vmess,
		Vless:        vless,
		Shadowsocks:  shadowsocks,
		Trojan:       trojan,
		Tuic:         tuic,
		AnyTls:       anyTLS,
		Hysteria:     hysteria,
		Hysteria2:    hysteria2,
		Common:       common,
		PushInterval: time.Second,
	}

	tests := []struct {
		name  string
		value any
	}{
		{name: "node pointer", value: node},
		{name: "node value", value: *node},
		{name: "common pointer", value: common},
		{name: "common value", value: *common},
		{name: "vmess pointer", value: vmess},
		{name: "vmess value", value: *vmess},
		{name: "vless pointer", value: vless},
		{name: "vless value", value: *vless},
		{name: "tls", value: tlsSettings},
		{name: "enc", value: encSettings},
		{name: "shadowsocks pointer", value: shadowsocks},
		{name: "shadowsocks value", value: *shadowsocks},
		{name: "trojan pointer", value: trojan},
		{name: "trojan value", value: *trojan},
		{name: "tuic pointer", value: tuic},
		{name: "tuic value", value: *tuic},
		{name: "anytls pointer", value: anyTLS},
		{name: "anytls value", value: *anyTLS},
		{name: "hysteria pointer", value: hysteria},
		{name: "hysteria value", value: *hysteria},
		{name: "hysteria2 pointer", value: hysteria2},
		{name: "hysteria2 value", value: *hysteria2},
		{name: "route", value: route},
		{name: "dns route", value: dnsRoute},
		{name: "raw dns", value: rawDNS},
		{name: "online user pointer", value: &onlineUser},
		{name: "online user value", value: onlineUser},
		{name: "rules", value: rules},
		{name: "user", value: user},
		{name: "user list", value: UserListBody{Users: []UserInfo{user}}},
	}
	secrets := []string{"action-secret", "route-secret", "match-secret", "route-dns-secret.example.com", "dns-action-secret", "dns-secret", "internal-dns-secret", "tls-sni-secret.example.com", "dest-secret.example.com", "short-id-secret", "private-secret", "seed-secret", "native-secret-mode", "enc-ticket-secret", "server-padding-secret", "enc-private-secret", "common-host-secret.example.com", "common-sni-secret.example.com", "push-secret", "pull-secret", "network-secret", "network-secret.example.com", "encryption-secret", "flow-secret", "cipher-secret", "server-key-secret", "obfs-secret", "trojan-network-secret.example.com", "congestion-secret", "padding-secret", "obfs-type-secret", "hysteria-obfs-secret", "obfs-password-secret", onlineUser.IP, "rules-regexp-secret.example.com", "rules-protocol-secret", user.Uuid}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputs := []string{fmt.Sprint(tt.value), fmt.Sprintf("%+v", tt.value), fmt.Sprintf("%#v", tt.value)}
			for _, output := range outputs {
				for _, secret := range secrets {
					if strings.Contains(output, secret) {
						t.Fatalf("formatted value leaked %q in %q", secret, output)
					}
				}
				if !strings.Contains(output, "REDACTED") {
					t.Fatalf("formatted value = %q, want REDACTED", output)
				}
			}
		})
	}
}

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

func TestIntervalToTimeInvalidStringLogRedactsValue(t *testing.T) {
	var output bytes.Buffer
	originalOutput := log.StandardLogger().Out
	log.SetOutput(&output)
	t.Cleanup(func() {
		log.SetOutput(originalOutput)
	})

	if got := IntervalToTime("token=interval-secret"); got != 0 {
		t.Fatalf("IntervalToTime() = %v, want 0", got)
	}

	capturedLogs := output.String()
	for _, leaked := range []string{"interval-secret", "token=interval-secret"} {
		if strings.Contains(capturedLogs, leaked) {
			t.Fatalf("captured logs leaked %q in %q", leaked, capturedLogs)
		}
	}
}

func TestValidateCommonNodeRejectsInvalidRoutes(t *testing.T) {
	tests := []struct {
		name string
		node *CommonNode
	}{
		{name: "unknown action", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: "unknown", Match: []string{"domain:example.com"}}}}},
		{name: "empty block match", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionBlock}}}},
		{name: "invalid dns action value", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: "not a host name"}}}},
		{name: "invalid dns host port userinfo", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: "user@example.com:53"}}}},
		{name: "invalid dns host port path", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: "example.com/path:53"}}}},
		{name: "invalid dns host port port", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: "example.com:70000"}}}},
		{name: "invalid main dns json", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: `main,{invalid-json}`}}}},
		{name: "empty route action value", node: &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionRoute, Match: []string{"domain:example.com"}}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateCommonNode(tt.node); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateDNSRouteAcceptsSafeActionValues(t *testing.T) {
	tests := []struct {
		name        string
		actionValue string
	}{
		{name: "ipv4", actionValue: "1.1.1.1"},
		{name: "hostname", actionValue: "dns.example.com"},
		{name: "hostname with port", actionValue: "dns.example.com:53"},
		{name: "bracketed ipv6 with port", actionValue: "[2001:4860:4860::8888]:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommonNode(&CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: tt.actionValue}}})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateDNSRouteRejectsUnsafeActionValues(t *testing.T) {
	tests := []struct {
		name        string
		actionValue string
	}{
		{name: "empty", actionValue: ""},
		{name: "url", actionValue: "https://dns.example.com"},
		{name: "query", actionValue: "dns.example.com?token=secret"},
		{name: "fragment", actionValue: "dns.example.com#fragment"},
		{name: "userinfo", actionValue: "user:pass@dns.example.com"},
		{name: "path", actionValue: "dns.example.com/path"},
		{name: "zero port", actionValue: "dns.example.com:0"},
		{name: "negative port", actionValue: "dns.example.com:-1"},
		{name: "high port", actionValue: "dns.example.com:65536"},
		{name: "whitespace", actionValue: "dns.example.com\n8.8.8.8"},
		{name: "dots only", actionValue: "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommonNode(&CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: tt.actionValue}}})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidationErrorsDoNotLeakRawExternalValues(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		leaked []string
	}{
		{
			name:   "invalid uuid",
			err:    validateUserList(&UserListBody{Users: []UserInfo{{Id: 1, Uuid: "not-a-secret-uuid"}}}),
			leaked: []string{"not-a-secret-uuid"},
		},
		{
			name:   "dns action value",
			err:    validateCommonNode(&CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: []string{"domain:example.com"}, ActionValue: "user:pass@dns.example.com?token=secret"}}}),
			leaked: []string{"user:pass", "secret", "dns.example.com"},
		},
		{
			name:   "online user entry",
			err:    validateOnlineUsers(map[int][]string{1: {"203.0.113.1_secret"}}),
			leaked: []string{"203.0.113.1_secret", "secret"},
		},
		{
			name:   "unsupported route action",
			err:    validateCommonNode(&CommonNode{ServerPort: 443, Routes: []Route{{Action: "token=secret", Match: []string{"domain:example.com"}}}}),
			leaked: []string{"token=secret", "secret"},
		},
		{
			name:   "unsupported node type",
			err:    validateConfig(&Config{APIHost: "http://127.0.0.1", Key: "token", NodeID: 1, NodeType: "token=secret"}),
			leaked: []string{"token=secret", "secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("expected error")
			}
			for _, leaked := range tt.leaked {
				if strings.Contains(tt.err.Error(), leaked) {
					t.Fatalf("error leaked %q in %q", leaked, tt.err.Error())
				}
			}
		})
	}
}

func TestValidateDNSRouteMainPreservesCommaJSONPayload(t *testing.T) {
	node := &CommonNode{ServerPort: 443, Routes: []Route{{Action: RouteActionDNS, Match: `main,{"servers":["1.1.1.1","8.8.8.8"]}`}}}
	if err := validateCommonNode(node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUserListRejectsInvalidUUID(t *testing.T) {
	err := validateUserList(&UserListBody{Users: []UserInfo{{Id: 1, Uuid: "not-a-uuid"}}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateUserListRejectsDuplicateUUID(t *testing.T) {
	duplicateUUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	err := validateUserList(&UserListBody{Users: []UserInfo{
		{Id: 1, Uuid: duplicateUUID},
		{Id: 2, Uuid: duplicateUUID},
	}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "duplicate user uuid") {
		t.Fatalf("error = %q, want duplicate user uuid", err.Error())
	}
}

func TestValidateUserListRejectsDuplicateUUIDWithDifferentCase(t *testing.T) {
	err := validateUserList(&UserListBody{Users: []UserInfo{
		{Id: 1, Uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
		{Id: 2, Uuid: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
	}})
	if err == nil {
		t.Fatal("expected error")
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
	if len(common.Routes) != 8 {
		t.Fatalf("common routes count = %d, want 8", len(common.Routes))
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
	if node.Routes[3].Action != RouteActionProtocol || !reflect.DeepEqual(node.Routes[3].Matches(), []string{"quic"}) {
		t.Fatalf("protocol route not preserved: %#v", node.Routes[3])
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
	if common.BaseConfig == nil {
		t.Fatal("common BaseConfig was cleared")
	}
}

func TestProcessCommonNode_DNSMainStringPreservesJSONWithCommas(t *testing.T) {
	node := &NodeInfo{RawDNS: RawDNS{DNSMap: map[string]map[string]interface{}{}, DNSJson: []byte{}}}
	common := &CommonNode{
		Routes: []Route{{Action: RouteActionDNS, Match: `main,{"servers":["1.1.1.1","8.8.8.8"]}`}},
	}

	node.ProcessCommonNode(common)

	want := `{"servers":["1.1.1.1","8.8.8.8"]}`
	if string(node.RawDNS.DNSJson) != want {
		t.Fatalf("DNSJson = %q, want %q", string(node.RawDNS.DNSJson), want)
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
