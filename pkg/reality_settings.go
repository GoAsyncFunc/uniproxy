package pkg

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// The REALITY helpers decode and length-check the values in the panel's
// tls_settings block. They validate shapes only; which combinations a node
// accepts remains the node's decision.

const (
	realityKeySize     = 32
	mldsa65SeedSize    = 32
	realityDefaultPort = "443"
	maxShortIDBytes    = 8
)

// DecodePrivateKey decodes tls_settings.private_key: base64url, 32 bytes.
func (t TlsSettings) DecodePrivateKey() ([]byte, error) {
	return decodeRealityKeyValue(t.PrivateKey, "private_key")
}

// DecodePublicKey decodes tls_settings.public_key: base64url, 32 bytes.
func (t TlsSettings) DecodePublicKey() ([]byte, error) {
	return decodeRealityKeyValue(t.PublicKey, "public_key")
}

func decodeRealityKeyValue(value, name string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("tls_settings.%s is empty", name)
	}
	key, err := settingsBase64URL(value)
	if err != nil {
		return nil, fmt.Errorf("tls_settings.%s is not base64url", name)
	}
	if len(key) != realityKeySize {
		return nil, fmt.Errorf("tls_settings.%s must decode to %d bytes", name, realityKeySize)
	}
	return key, nil
}

// DecodeShortID decodes tls_settings.short_id: hexadecimal, 1 to 8 bytes. Xray
// pads shorter values with zero bytes, so callers compare decoded bytes rather
// than text.
func (t TlsSettings) DecodeShortID() ([]byte, error) {
	value := t.ShortId
	if value == "" {
		return nil, fmt.Errorf("tls_settings.short_id is empty")
	}
	if len(value)%2 != 0 {
		value = "0" + value
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("tls_settings.short_id is not hexadecimal")
	}
	if len(decoded) == 0 || len(decoded) > maxShortIDBytes {
		return nil, fmt.Errorf("tls_settings.short_id must decode to 1 to %d bytes", maxShortIDBytes)
	}
	return decoded, nil
}

// Destination returns tls_settings.dest, or derives it from server_name and
// server_port when dest is empty, defaulting the port to 443.
func (t TlsSettings) Destination() (string, error) {
	if t.Dest != "" {
		return t.Dest, nil
	}
	if t.ServerName == "" {
		return "", fmt.Errorf("tls_settings.dest and server_name are both empty")
	}
	port := t.ServerPort
	if port == "" {
		port = realityDefaultPort
	}
	if strings.Contains(t.ServerName, ":") && !strings.HasPrefix(t.ServerName, "[") {
		// An IPv6 literal needs brackets before a port is appended.
		return "[" + t.ServerName + "]:" + port, nil
	}
	return t.ServerName + ":" + port, nil
}

// DecodeMLDSA65Seed decodes tls_settings.mldsa65Seed: base64url, 32 bytes.
func (t TlsSettings) DecodeMLDSA65Seed() ([]byte, error) {
	if t.Mldsa65Seed == "" {
		return nil, fmt.Errorf("tls_settings.mldsa65Seed is empty")
	}
	seed, err := settingsBase64URL(t.Mldsa65Seed)
	if err != nil {
		return nil, fmt.Errorf("tls_settings.mldsa65Seed is not base64url")
	}
	if len(seed) != mldsa65SeedSize {
		return nil, fmt.Errorf("tls_settings.mldsa65Seed must decode to %d bytes", mldsa65SeedSize)
	}
	return seed, nil
}
