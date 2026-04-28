package pkg

import (
	"strings"
	"testing"
)

// TestVlessHandler_v2boardFormat verifies parsing of v2board's UniProxyController
// response format for VLESS, which uses camelCase "networkSettings" (not snake_case).
// See v2board/app/Http/Controllers/V1/Server/UniProxyController.php line 208.
func TestVlessHandler_v2boardFormat(t *testing.T) {
	body := []byte(`{
		"server_port": 443,
		"network": "ws",
		"networkSettings": {"path": "/vless", "headers": {"Host": "example.com"}},
		"tls": 2,
		"flow": "xtls-rprx-vision",
		"tls_settings": {
			"server_name": "example.com",
			"private_key": "priv",
			"short_id": "0123abcd",
			"server_port": "443"
		},
		"encryption": "none",
		"encryption_settings": {},
		"base_config": {"push_interval": 60, "pull_interval": 60}
	}`)

	info := &NodeInfo{Id: 1, Type: Vless}
	h := &VlessHandler{}
	cm, err := h.ParseConfig(info, body)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if info.Vless == nil {
		t.Fatal("info.Vless not set")
	}
	if len(info.Vless.NetworkSettings) == 0 {
		t.Fatal("NetworkSettings empty - v2board sends camelCase 'networkSettings'")
	}
	if info.Vless.Network != "ws" {
		t.Errorf("Network = %q, want 'ws'", info.Vless.Network)
	}
	if info.Vless.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q", info.Vless.Flow)
	}
	if info.Vless.TlsSettings.ShortId != "0123abcd" {
		t.Errorf("ShortId = %q", info.Vless.TlsSettings.ShortId)
	}
	if info.Security != Reality {
		t.Errorf("Security = %d, want %d (Reality)", info.Security, Reality)
	}
	if cm == nil {
		t.Fatal("CommonNode nil")
	}
	if cm.ServerPort != 443 {
		t.Errorf("ServerPort = %d", cm.ServerPort)
	}
}

// TestVMessHandler_v2boardFormat verifies v2board's UniProxyController VMess response
// also uses camelCase "networkSettings". See UniProxyController.php line 200.
func TestNodeHandlers_ParseProtocolConfigs(t *testing.T) {
	tests := []struct {
		name          string
		handler       NodeHandler
		body          string
		wantSecurity  int
		wantPort      int
		assertInfoSet func(*testing.T, *NodeInfo)
	}{
		{
			name:         "shadowsocks",
			handler:      &ShadowsocksHandler{},
			body:         `{"server_port": 8388, "cipher": "aes-256-gcm", "server_key": "key", "obfs": "http", "obfs_settings": {"host": "example.com"}}`,
			wantSecurity: None,
			wantPort:     8388,
			assertInfoSet: func(t *testing.T, info *NodeInfo) {
				t.Helper()
				if info.Shadowsocks == nil || info.Shadowsocks.Cipher != "aes-256-gcm" {
					t.Fatalf("Shadowsocks = %#v", info.Shadowsocks)
				}
			},
		},
		{
			name:         "trojan",
			handler:      &TrojanHandler{},
			body:         `{"server_port": 443, "server_name": "trojan.example", "network": "tcp", "networkSettings": {"header": {"type": "none"}}}`,
			wantSecurity: Tls,
			wantPort:     443,
			assertInfoSet: func(t *testing.T, info *NodeInfo) {
				t.Helper()
				if info.Trojan == nil || info.Trojan.Network != "tcp" {
					t.Fatalf("Trojan = %#v", info.Trojan)
				}
			},
		},
		{
			name:         "tuic",
			handler:      &TuicHandler{},
			body:         `{"server_port": 8443, "server_name": "tuic.example", "congestion_control": "bbr", "zero_rtt_handshake": true}`,
			wantSecurity: Tls,
			wantPort:     8443,
			assertInfoSet: func(t *testing.T, info *NodeInfo) {
				t.Helper()
				if info.Tuic == nil || info.Tuic.CongestionControl != "bbr" || !info.Tuic.ZeroRTTHandshake {
					t.Fatalf("Tuic = %#v", info.Tuic)
				}
			},
		},
		{
			name:         "hysteria",
			handler:      &HysteriaHandler{},
			body:         `{"server_port": 8443, "server_name": "hy.example", "version": 1, "up_mbps": 100, "down_mbps": 200, "obfs": "secret"}`,
			wantSecurity: Tls,
			wantPort:     8443,
			assertInfoSet: func(t *testing.T, info *NodeInfo) {
				t.Helper()
				if info.Hysteria == nil || info.Hysteria.UpMbps != 100 || info.Hysteria.Obfs != "secret" {
					t.Fatalf("Hysteria = %#v", info.Hysteria)
				}
			},
		},
		{
			name:         "hysteria2",
			handler:      &Hysteria2Handler{},
			body:         `{"server_port": 8443, "server_name": "hy2.example", "version": 2, "ignore_client_bandwidth": true, "up_mbps": 100, "down_mbps": 200, "obfs": "salamander", "obfs-password": "secret"}`,
			wantSecurity: Tls,
			wantPort:     8443,
			assertInfoSet: func(t *testing.T, info *NodeInfo) {
				t.Helper()
				if info.Hysteria2 == nil || !info.Hysteria2.IgnoreClientBandwidth || info.Hysteria2.ObfsPassword != "secret" {
					t.Fatalf("Hysteria2 = %#v", info.Hysteria2)
				}
			},
		},
		{
			name:         "anytls",
			handler:      &AnyTlsHandler{},
			body:         `{"server_port": 443, "server_name": "anytls.example", "padding_scheme": ["stop=8", "0=30-30"]}`,
			wantSecurity: Tls,
			wantPort:     443,
			assertInfoSet: func(t *testing.T, info *NodeInfo) {
				t.Helper()
				if info.AnyTls == nil || len(info.AnyTls.PaddingScheme) != 2 {
					t.Fatalf("AnyTls = %#v", info.AnyTls)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &NodeInfo{Id: 1, Type: tt.name}
			cm, err := tt.handler.ParseConfig(info, []byte(tt.body))
			if err != nil {
				t.Fatalf("ParseConfig failed: %v", err)
			}
			if cm == nil {
				t.Fatal("CommonNode nil")
			}
			if cm.ServerPort != tt.wantPort {
				t.Fatalf("ServerPort = %d, want %d", cm.ServerPort, tt.wantPort)
			}
			if info.Security != tt.wantSecurity {
				t.Fatalf("Security = %d, want %d", info.Security, tt.wantSecurity)
			}
			tt.assertInfoSet(t, info)
		})
	}
}

func TestNodeHandlers_ReturnErrorsForMalformedJSON(t *testing.T) {
	tests := []struct {
		name    string
		handler NodeHandler
	}{
		{name: "vmess", handler: &VMessHandler{}},
		{name: "vless", handler: &VlessHandler{}},
		{name: "shadowsocks", handler: &ShadowsocksHandler{}},
		{name: "trojan", handler: &TrojanHandler{}},
		{name: "tuic", handler: &TuicHandler{}},
		{name: "hysteria", handler: &HysteriaHandler{}},
		{name: "hysteria2", handler: &Hysteria2Handler{}},
		{name: "anytls", handler: &AnyTlsHandler{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.handler.ParseConfig(&NodeInfo{}, []byte("not valid json"))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "decode "+tt.name+" params error") {
				t.Fatalf("error = %q", err.Error())
			}
		})
	}
}

func TestNodeHandlers_ReturnErrorForNilNodeInfo(t *testing.T) {
	tests := []struct {
		name    string
		handler NodeHandler
	}{
		{name: "vmess", handler: &VMessHandler{}},
		{name: "vless", handler: &VlessHandler{}},
		{name: "shadowsocks", handler: &ShadowsocksHandler{}},
		{name: "trojan", handler: &TrojanHandler{}},
		{name: "tuic", handler: &TuicHandler{}},
		{name: "hysteria", handler: &HysteriaHandler{}},
		{name: "hysteria2", handler: &Hysteria2Handler{}},
		{name: "anytls", handler: &AnyTlsHandler{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.handler.ParseConfig(nil, []byte(`{"server_port": 443}`))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "node info is nil") {
				t.Fatalf("error = %q", err.Error())
			}
		})
	}
}

func TestVMessHandler_v2boardFormat(t *testing.T) {
	body := []byte(`{
		"server_port": 10086,
		"network": "tcp",
		"networkSettings": {"header": {"type": "none"}},
		"tls": 1
	}`)

	info := &NodeInfo{Id: 1, Type: Vmess}
	h := &VMessHandler{}
	if _, err := h.ParseConfig(info, body); err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if info.VMess == nil {
		t.Fatal("info.VMess not set")
	}
	if len(info.VMess.NetworkSettings) == 0 {
		t.Fatal("NetworkSettings empty - v2board sends camelCase 'networkSettings'")
	}
	if info.VMess.Network != "tcp" {
		t.Errorf("Network = %q", info.VMess.Network)
	}
	if info.Security != Tls {
		t.Errorf("Security = %d, want %d", info.Security, Tls)
	}
}
