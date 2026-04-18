package pkg

import (
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
