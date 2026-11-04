package pkg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

func encodeFixtureKey(size int) string {
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func TestTlsSettingsDecodeRealityKeys(t *testing.T) {
	encoded := encodeFixtureKey(realityKeySize)
	settings := TlsSettings{PrivateKey: encoded, PublicKey: encoded}
	privateKey, err := settings.DecodePrivateKey()
	if err != nil || len(privateKey) != realityKeySize {
		t.Fatalf("DecodePrivateKey = %d bytes, %v", len(privateKey), err)
	}
	publicKey, err := settings.DecodePublicKey()
	if err != nil || len(publicKey) != realityKeySize {
		t.Fatalf("DecodePublicKey = %d bytes, %v", len(publicKey), err)
	}
	if !bytes.Equal(privateKey, publicKey) {
		t.Fatal("the same encoding decoded differently")
	}
	for _, value := range []string{"", encodeFixtureKey(realityKeySize - 1), encodeFixtureKey(realityKeySize + 1), "not base64url!"} {
		if _, err := (TlsSettings{PrivateKey: value}).DecodePrivateKey(); err == nil {
			t.Errorf("DecodePrivateKey(%q) accepted", value)
		}
	}
	for _, value := range []string{"", encodeFixtureKey(16), "++"} {
		if _, err := (TlsSettings{PublicKey: value}).DecodePublicKey(); err == nil {
			t.Errorf("DecodePublicKey(%q) accepted", value)
		}
	}
	padded := base64.URLEncoding.EncodeToString(make([]byte, realityKeySize))
	if key, err := (TlsSettings{PublicKey: padded}).DecodePublicKey(); err != nil || len(key) != realityKeySize {
		t.Fatalf("padded key rejected: %v", err)
	}
}

func TestTlsSettingsDecodeShortID(t *testing.T) {
	for _, test := range []struct {
		value string
		want  []byte
	}{
		{"ab", []byte{0xab}},
		{"abcdef01", []byte{0xab, 0xcd, 0xef, 0x01}},
		{"a", []byte{0x0a}},
		{"0", []byte{0x00}},
		{"0000000000000001", []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	} {
		decoded, err := (TlsSettings{ShortId: test.value}).DecodeShortID()
		if err != nil || !bytes.Equal(decoded, test.want) {
			t.Errorf("DecodeShortID(%q) = %v, %v; want %v", test.value, decoded, err, test.want)
		}
	}
	for _, value := range []string{"", "zz", "xyz", "001122334455667788"} {
		if _, err := (TlsSettings{ShortId: value}).DecodeShortID(); err == nil {
			t.Errorf("DecodeShortID(%q) accepted", value)
		}
	}
}

func TestTlsSettingsDestination(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings TlsSettings
		want     string
	}{
		{"dest", TlsSettings{Dest: "www.example.com:443"}, "www.example.com:443"},
		{"name-and-port", TlsSettings{ServerName: "www.example.com", ServerPort: "8443"}, "www.example.com:8443"},
		{"name-default-port", TlsSettings{ServerName: "www.example.com"}, "www.example.com:443"},
		{"ipv6", TlsSettings{ServerName: "2001:db8::1", ServerPort: "8443"}, "[2001:db8::1]:8443"},
		{"ipv6-bracketed", TlsSettings{ServerName: "[2001:db8::1]"}, "[2001:db8::1]:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.settings.Destination()
			if err != nil || got != test.want {
				t.Fatalf("Destination() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	for _, settings := range []TlsSettings{{}, {ServerPort: "8443"}} {
		if _, err := settings.Destination(); err == nil {
			t.Errorf("Destination(%+v) accepted", settings)
		}
	}
}

func TestTlsSettingsDecodeMLDSA65Seed(t *testing.T) {
	seed, err := (TlsSettings{Mldsa65Seed: encodeFixtureKey(mldsa65SeedSize)}).DecodeMLDSA65Seed()
	if err != nil || len(seed) != mldsa65SeedSize {
		t.Fatalf("DecodeMLDSA65Seed = %d bytes, %v", len(seed), err)
	}
	for _, settings := range []TlsSettings{{}, {Mldsa65Seed: encodeFixtureKey(mldsa65SeedSize - 1)}, {Mldsa65Seed: "!!"}} {
		if _, err := settings.DecodeMLDSA65Seed(); err == nil {
			t.Errorf("DecodeMLDSA65Seed(%q) accepted", settings.Mldsa65Seed)
		}
	}
}

func TestTlsSettingsPanelShapes(t *testing.T) {
	for _, raw := range []string{"null", "[]"} {
		settings := TlsSettings{Xver: 2, ServerName: "unchanged"}
		if err := json.Unmarshal([]byte(raw), &settings); err != nil {
			t.Fatalf("unmarshal %q: %v", raw, err)
		}
		if !reflect.DeepEqual(settings, TlsSettings{}) {
			t.Fatalf("%q left %+v", raw, settings)
		}
	}
	var settings TlsSettings
	if err := json.Unmarshal([]byte(`{"server_port":443,"ech":"true","ech_config":"AABB"}`), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.ServerPort != "443" || settings.Ech != "true" || !reflect.DeepEqual(settings.EchConfig, []string{"AABB"}) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	if err := json.Unmarshal([]byte(`{"server_port":"8443","ech_config":["a","b"]}`), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.ServerPort != "8443" || !reflect.DeepEqual(settings.EchConfig, []string{"a", "b"}) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	if err := json.Unmarshal([]byte(`{"server_port":null,"ech_config":[]}`), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.ServerPort != "" || len(settings.EchConfig) != 0 {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	for _, raw := range []string{`{"ech_config":3}`, `{"ech_config":{"a":1}}`, `{"server_port":{}}`, `{"server_port":true}`} {
		if err := json.Unmarshal([]byte(raw), &settings); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}

func TestEncSettingsPanelShapes(t *testing.T) {
	for _, raw := range []string{"null", "[]"} {
		settings := EncSettings{Mode: "unchanged"}
		if err := json.Unmarshal([]byte(raw), &settings); err != nil {
			t.Fatalf("unmarshal %q: %v", raw, err)
		}
		if !reflect.DeepEqual(settings, EncSettings{}) {
			t.Fatalf("%q left %+v", raw, settings)
		}
	}
	var settings EncSettings
	body := `{"mode":"native","rtt":"1rtt","ticket":"fixture-ticket","server_padding":"fixture-padding","private_key":"` + encodeFixtureKey(32) + `"}`
	if err := json.Unmarshal([]byte(body), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Mode != "native" || settings.Rtt != "1rtt" || settings.Ticket != "fixture-ticket" {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	key, kind, err := settings.DecodeKey()
	if err != nil || kind != EncKeyX25519 || len(key) != 32 {
		t.Fatalf("DecodeKey = %d bytes, %q, %v", len(key), kind, err)
	}
	for _, test := range []struct {
		raw    string
		kind   EncKeyKind
		length int
	}{
		{`{}`, EncKeyNone, 0},
		{`{"private_key":""}`, EncKeyNone, 0},
		{`[]`, EncKeyNone, 0},
		{`{"private_key":"` + encodeFixtureKey(64) + `"}`, EncKeyOther, 64},
	} {
		var decoded EncSettings
		if err := json.Unmarshal([]byte(test.raw), &decoded); err != nil {
			t.Fatal(err)
		}
		key, kind, err := decoded.DecodeKey()
		if err != nil || kind != test.kind || len(key) != test.length {
			t.Errorf("DecodeKey(%s) = %d bytes, %q, %v; want %d bytes, %q", test.raw, len(key), kind, err, test.length, test.kind)
		}
	}
	var broken EncSettings
	if err := json.Unmarshal([]byte(`{"private_key":"not base64url!"}`), &broken); err != nil {
		t.Fatal(err)
	}
	if _, _, err := broken.DecodeKey(); err == nil {
		t.Error("a malformed private key was accepted")
	}
}
