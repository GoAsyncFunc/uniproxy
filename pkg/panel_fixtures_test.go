package pkg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type panelFixture struct {
	Name     string
	Protocol string
	Path     string
	Body     []byte
}

func TestPanelFixtures(t *testing.T) {
	fixtures := loadPanelFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("expected at least one panel fixture")
	}

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if fixture.Protocol == "common" {
				testCommonFixture(t, fixture)
				return
			}

			handler := handlerForProtocol(t, fixture.Protocol)
			info := &NodeInfo{Id: 1, Type: fixture.Protocol}
			common, err := handler.ParseConfig(info, fixture.Body)
			if err != nil {
				t.Fatalf("ParseConfig failed: %v", err)
			}
			assertParsedFixture(t, fixture, info, common)
		})
	}
}

func TestRealPanelFixturesAreSanitized(t *testing.T) {
	unsafeFixtures := map[string][]byte{
		"token and host":           []byte(`{"token":"production-token","host":"panel.internal"}`),
		"protocol secrets":         []byte(`{"obfs-password":"real-password","mldsa65Seed":"real-seed","ticket":"real-ticket","password":"real-password"}`),
		"endpoint host":            []byte(`{"dest":"internal.panel:443"}`),
		"invalid documentation ip": []byte(`{"host":"192.0.2.evil"}`),
	}
	for name, body := range unsafeFixtures {
		t.Run("rejects "+name, func(t *testing.T) {
			if err := realPanelFixtureSanitizationError(body); err == nil {
				t.Fatal("expected unsafe fixture to be rejected")
			}
		})
	}

	fixtures := loadPanelFixtures(t)
	for _, fixture := range fixtures {
		if !strings.Contains(filepath.ToSlash(fixture.Path), "/real/") {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			if err := realPanelFixtureSanitizationError(fixture.Body); err != nil {
				t.Fatalf("real fixture is not sanitized: %v", err)
			}
		})
	}
}

func realPanelFixtureSanitizationError(body []byte) error {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return fmt.Errorf("decode fixture json: %w", err)
	}
	return validateSanitizedFixtureValue("", value)
}

func validateSanitizedFixtureValue(key string, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, childValue := range typed {
			if err := validateSanitizedFixtureValue(childKey, childValue); err != nil {
				return err
			}
		}
	case []any:
		for _, childValue := range typed {
			if err := validateSanitizedFixtureValue(key, childValue); err != nil {
				return err
			}
		}
	case string:
		if !isSanitizedFixtureString(key, typed) {
			return fmt.Errorf("field %q contains unsanitized value %q", key, typed)
		}
	}
	return nil
}

func isSanitizedFixtureString(key string, value string) bool {
	if value == "" {
		return true
	}
	normalizedKey := normalizeFixtureKey(key)
	if isSensitiveFixtureKey(normalizedKey) {
		return strings.HasPrefix(value, "fixture-")
	}
	if isHostFixtureKey(normalizedKey) {
		return value == "example.com" || strings.HasSuffix(value, ".example.com") || isDocumentationIP(value)
	}
	return true
}

func normalizeFixtureKey(key string) string {
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "-", "_")
	return key
}

func isSensitiveFixtureKey(key string) bool {
	switch key {
	case "token", "key", "private_key", "privatekey", "server_key", "serverkey", "client_secret", "authorization", "password", "pass", "secret", "obfs_password", "mldsa65seed", "ticket", "auth", "api_key", "apikey", "access_token", "refresh_token", "id_token", "signature", "sig":
		return true
	default:
		return false
	}
}

func isHostFixtureKey(key string) bool {
	switch key {
	case "host", "server_name", "servername", "sni", "dest", "address", "server", "servers", "url", "endpoint", "origin":
		return true
	default:
		return false
	}
}

func isDocumentationIP(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && (isIPv4DocumentationRange(ip, 192, 0, 2) || isIPv4DocumentationRange(ip, 198, 51, 100) || isIPv4DocumentationRange(ip, 203, 0, 113))
}

func isIPv4DocumentationRange(ip net.IP, a byte, b byte, c byte) bool {
	ipv4 := ip.To4()
	return ipv4 != nil && ipv4[0] == a && ipv4[1] == b && ipv4[2] == c
}

func loadPanelFixtures(t *testing.T) []panelFixture {
	t.Helper()

	var fixtures []panelFixture
	roots := []string{
		filepath.Join("testdata", "panels", "synthetic"),
		filepath.Join("testdata", "panels", "real"),
	}

	for _, root := range roots {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fixtures = append(fixtures, panelFixture{
				Name:     fixtureName(path),
				Protocol: protocolFromFixturePath(t, path),
				Path:     path,
				Body:     body,
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk fixtures under %s: %v", root, err)
		}
	}

	return fixtures
}

func fixtureName(path string) string {
	name := strings.TrimSuffix(path, filepath.Ext(path))
	return filepath.ToSlash(name)
}

func protocolFromFixturePath(t *testing.T, path string) string {
	t.Helper()

	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		if part == "synthetic" && i+1 < len(parts) {
			return parts[i+1]
		}
		if part == "real" && i+2 < len(parts) {
			return parts[i+2]
		}
	}
	t.Fatalf("cannot infer protocol from fixture path %q", path)
	return ""
}

func handlerForProtocol(t *testing.T, protocol string) NodeHandler {
	t.Helper()

	switch protocol {
	case Vmess:
		return &VMessHandler{}
	case Vless:
		return &VlessHandler{}
	case Shadowsocks:
		return &ShadowsocksHandler{}
	case Trojan:
		return &TrojanHandler{}
	case Tuic:
		return &TuicHandler{}
	case Hysteria:
		return &HysteriaHandler{}
	case Hysteria2:
		return &Hysteria2Handler{}
	case AnyTls:
		return &AnyTlsHandler{}
	default:
		t.Fatalf("unsupported fixture protocol %q", protocol)
		return nil
	}
}

func testCommonFixture(t *testing.T, fixture panelFixture) {
	t.Helper()

	var common CommonNode
	if err := json.Unmarshal(fixture.Body, &common); err != nil {
		t.Fatalf("decode common fixture: %v", err)
	}
	if err := validateCommonNode(&common); err != nil {
		t.Fatalf("validateCommonNode failed: %v", err)
	}

	info := &NodeInfo{Id: 1, Type: "common"}
	info.ProcessCommonNode(&common)
	if len(info.Routes) != len(common.Routes) {
		t.Fatalf("Routes length = %d, want %d", len(info.Routes), len(common.Routes))
	}
	if info.PushInterval == 0 || info.PullInterval == 0 {
		t.Fatalf("intervals not normalized: push=%v pull=%v", info.PushInterval, info.PullInterval)
	}
	if len(info.RawDNS.DNSJson) == 0 {
		t.Fatal("expected main DNS JSON to be preserved")
	}
}

func assertParsedFixture(t *testing.T, fixture panelFixture, info *NodeInfo, common *CommonNode) {
	t.Helper()

	if common == nil {
		t.Fatal("CommonNode nil")
	}
	if err := validateCommonNode(common); err != nil {
		t.Fatalf("validateCommonNode failed: %v", err)
	}
	if err := validateProtocolSpecificNode(info); err != nil {
		t.Fatalf("validateProtocolSpecificNode failed: %v", err)
	}

	info.ProcessCommonNode(common)
	if common.ServerPort <= 0 || common.ServerPort > 65535 {
		t.Fatalf("ServerPort = %d", common.ServerPort)
	}
	assertProtocolStructSet(t, fixture.Protocol, info)
	assertCompatibilityFields(t, fixture, info)
}

func assertProtocolStructSet(t *testing.T, protocol string, info *NodeInfo) {
	t.Helper()

	switch protocol {
	case Vmess:
		if info.VMess == nil {
			t.Fatal("VMess not set")
		}
	case Vless:
		if info.Vless == nil {
			t.Fatal("Vless not set")
		}
	case Shadowsocks:
		if info.Shadowsocks == nil {
			t.Fatal("Shadowsocks not set")
		}
	case Trojan:
		if info.Trojan == nil {
			t.Fatal("Trojan not set")
		}
	case Tuic:
		if info.Tuic == nil {
			t.Fatal("Tuic not set")
		}
	case Hysteria:
		if info.Hysteria == nil {
			t.Fatal("Hysteria not set")
		}
	case Hysteria2:
		if info.Hysteria2 == nil {
			t.Fatal("Hysteria2 not set")
		}
	case AnyTls:
		if info.AnyTls == nil {
			t.Fatal("AnyTls not set")
		}
	}
}

func assertCompatibilityFields(t *testing.T, fixture panelFixture, info *NodeInfo) {
	t.Helper()

	name := filepath.Base(fixture.Path)
	switch {
	case fixture.Protocol == Vmess && strings.Contains(name, "network-settings"):
		if len(info.VMess.NetworkSettings) == 0 {
			t.Fatal("VMess NetworkSettings empty")
		}
		if info.Security != Tls {
			t.Fatalf("Security = %d, want %d", info.Security, Tls)
		}
	case fixture.Protocol == Vless && strings.Contains(name, "network-settings"):
		if len(info.Vless.NetworkSettings) == 0 {
			t.Fatal("Vless NetworkSettings empty")
		}
		if info.Vless.TlsSettings.ShortId != "0123abcd" {
			t.Fatalf("ShortId = %q", info.Vless.TlsSettings.ShortId)
		}
		if info.Security != Reality {
			t.Fatalf("Security = %d, want %d", info.Security, Reality)
		}
	case fixture.Protocol == Hysteria2 && strings.Contains(name, "obfs-password"):
		if info.Hysteria2.ObfsPassword != "secret" {
			t.Fatalf("ObfsPassword = %q", info.Hysteria2.ObfsPassword)
		}
	case fixture.Protocol == AnyTls && strings.Contains(name, "padding-scheme"):
		if len(info.AnyTls.PaddingScheme) != 2 {
			t.Fatalf("PaddingScheme = %#v", info.AnyTls.PaddingScheme)
		}
	}
}
