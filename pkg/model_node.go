package pkg

import (
	"encoding/json"
	"fmt"
)

// VMessNode is vmess node info
type VMessNode struct {
	CommonNode
	Tls                int             `json:"tls"`
	TlsSettings        TlsSettings     `json:"tls_settings"`
	Network            string          `json:"network"`
	NetworkSettings    json.RawMessage `json:"networkSettings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
}

func (n VMessNode) String() string {
	return fmt.Sprintf("{CommonNode:%s Tls:%d TlsSettings:REDACTED Network:REDACTED NetworkSettings:REDACTED Encryption:REDACTED EncryptionSettings:REDACTED}", n.CommonNode.String(), n.Tls)
}

func (n VMessNode) GoString() string {
	return n.String()
}

func (n *VMessNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

// VlessNode is vless node info
type VlessNode struct {
	CommonNode
	Tls                int             `json:"tls"`
	TlsSettings        TlsSettings     `json:"tls_settings"`
	Network            string          `json:"network"`
	NetworkSettings    json.RawMessage `json:"networkSettings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
	Flow               string          `json:"flow"`
	RealityConfig      RealityConfig   `json:"-"`
}

func (n VlessNode) String() string {
	return fmt.Sprintf("{CommonNode:%s Tls:%d TlsSettings:REDACTED Network:REDACTED NetworkSettings:REDACTED Encryption:REDACTED EncryptionSettings:REDACTED Flow:REDACTED RealityConfig:REDACTED}", n.CommonNode.String(), n.Tls)
}

func (n VlessNode) GoString() string {
	return n.String()
}

func (n *VlessNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

// TlsSettings is the panel's TLS and REALITY settings block. Untouched
// settings arrive as an empty array, numbers may arrive as strings, and
// ech_config may be a single string or a list; UnmarshalJSON normalizes those
// shapes. See DecodePrivateKey, DecodePublicKey, DecodeShortID, Destination and
// DecodeMLDSA65Seed for the REALITY helpers.
type TlsSettings struct {
	ServerName  string   `json:"server_name"`
	Dest        string   `json:"dest"`
	ServerPort  string   `json:"server_port"`
	ShortId     string   `json:"short_id"`
	PrivateKey  string   `json:"private_key"`
	PublicKey   string   `json:"public_key"`
	Mldsa65Seed string   `json:"mldsa65Seed"`
	Ech         string   `json:"ech"`
	EchConfig   []string `json:"ech_config"`
	Xver        uint64   `json:"xver"`
}

// UnmarshalJSON accepts the shapes panel editors emit: absent, null and [] for
// untouched settings; server_port as a number or a string; ech_config as a
// string or a list of strings; and xver as an integer or an integer string from
// 0 to 2, absent meaning no PROXY protocol.
func (t *TlsSettings) UnmarshalJSON(data []byte) error {
	if settingsEmpty(data) {
		*t = TlsSettings{}
		return nil
	}
	var decoded struct {
		ServerName  string          `json:"server_name"`
		Dest        string          `json:"dest"`
		ServerPort  json.RawMessage `json:"server_port"`
		ShortId     string          `json:"short_id"`
		PrivateKey  string          `json:"private_key"`
		PublicKey   string          `json:"public_key"`
		Mldsa65Seed string          `json:"mldsa65Seed"`
		Ech         string          `json:"ech"`
		EchConfig   json.RawMessage `json:"ech_config"`
		Xver        json.RawMessage `json:"xver"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	port, err := settingsStringOrNumber(decoded.ServerPort)
	if err != nil {
		return fmt.Errorf("server_port must be a string or a number")
	}
	echConfig, err := settingsStringList(decoded.EchConfig)
	if err != nil {
		return fmt.Errorf("ech_config must be a string or a list of strings")
	}
	xver, err := settingsXver(decoded.Xver)
	if err != nil {
		return err
	}
	*t = TlsSettings{
		ServerName:  decoded.ServerName,
		Dest:        decoded.Dest,
		ServerPort:  port,
		ShortId:     decoded.ShortId,
		PrivateKey:  decoded.PrivateKey,
		PublicKey:   decoded.PublicKey,
		Mldsa65Seed: decoded.Mldsa65Seed,
		Ech:         decoded.Ech,
		EchConfig:   echConfig,
		Xver:        xver,
	}
	return nil
}

func (t TlsSettings) String() string {
	return "{ServerName:REDACTED Dest:REDACTED ServerPort:REDACTED ShortId:REDACTED PrivateKey:REDACTED PublicKey:REDACTED Mldsa65Seed:REDACTED Ech:REDACTED EchConfig:REDACTED Xver:REDACTED}"
}

func (t TlsSettings) GoString() string {
	return t.String()
}

// EncKeyKind classifies an encryption private key by its decoded length.
type EncKeyKind string

const (
	// EncKeyNone means no key is configured.
	EncKeyNone EncKeyKind = ""
	// EncKeyX25519 is a 32-byte X25519 key, what the panel generates.
	EncKeyX25519 EncKeyKind = "x25519"
	// EncKeyOther is a well-formed key of another length, such as a 64-byte
	// ML-KEM-768 seed typed by hand.
	EncKeyOther EncKeyKind = "other"
)

// EncSettings is the panel's VLESS encryption settings block. Untouched
// settings arrive as an empty array, which UnmarshalJSON treats as absent.
type EncSettings struct {
	Mode          string `json:"mode"`
	Rtt           string `json:"rtt"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

// UnmarshalJSON accepts absent, null and [] for untouched settings.
func (e *EncSettings) UnmarshalJSON(data []byte) error {
	if settingsEmpty(data) {
		*e = EncSettings{}
		return nil
	}
	type alias EncSettings
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*e = EncSettings(decoded)
	return nil
}

// DecodeKey returns the decoded private key and its kind. The library reports
// the shape only; whether a node supports a kind is the node's decision.
func (e EncSettings) DecodeKey() ([]byte, EncKeyKind, error) {
	if e.PrivateKey == "" {
		return nil, EncKeyNone, nil
	}
	key, err := settingsBase64URL(e.PrivateKey)
	if err != nil {
		return nil, EncKeyNone, fmt.Errorf("private_key is not base64url")
	}
	if len(key) == 0 {
		return nil, EncKeyNone, fmt.Errorf("private_key is empty")
	}
	if len(key) == x25519KeySize {
		return key, EncKeyX25519, nil
	}
	return key, EncKeyOther, nil
}

func (e EncSettings) String() string {
	return "{Mode:REDACTED Rtt:REDACTED Ticket:REDACTED ServerPadding:REDACTED PrivateKey:REDACTED}"
}

func (e EncSettings) GoString() string {
	return e.String()
}

type RealityConfig struct {
	Xver         uint64 `json:"Xver"`
	MinClientVer string `json:"MinClientVer"`
	MaxClientVer string `json:"MaxClientVer"`
	MaxTimeDiff  string `json:"MaxTimeDiff"`
}

type ShadowsocksNode struct {
	CommonNode
	Cipher       string          `json:"cipher"`
	ServerKey    string          `json:"server_key"`
	Obfs         string          `json:"obfs"`
	ObfsSettings json.RawMessage `json:"obfs_settings"`
}

func (n ShadowsocksNode) String() string {
	return "{Cipher:REDACTED ServerKey:REDACTED Obfs:REDACTED ObfsSettings:REDACTED}"
}

func (n ShadowsocksNode) GoString() string {
	return n.String()
}

func (n *ShadowsocksNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type TrojanNode struct {
	CommonNode
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
}

func (n TrojanNode) String() string {
	return fmt.Sprintf("{CommonNode:%s Network:REDACTED NetworkSettings:REDACTED}", n.CommonNode.String())
}

func (n TrojanNode) GoString() string {
	return n.String()
}

func (n *TrojanNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type TuicNode struct {
	CommonNode
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
}

func (n TuicNode) String() string {
	return fmt.Sprintf("{CommonNode:%s CongestionControl:REDACTED ZeroRTTHandshake:%t}", n.CommonNode.String(), n.ZeroRTTHandshake)
}

func (n TuicNode) GoString() string {
	return n.String()
}

func (n *TuicNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type AnyTlsNode struct {
	CommonNode
	PaddingScheme []string `json:"padding_scheme,omitempty"`
}

func (n AnyTlsNode) String() string {
	return fmt.Sprintf("{CommonNode:%s PaddingScheme:%d REDACTED}", n.CommonNode.String(), len(n.PaddingScheme))
}

func (n AnyTlsNode) GoString() string {
	return n.String()
}

func (n *AnyTlsNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type HysteriaNode struct {
	CommonNode
	Version  int    `json:"version"`
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	Obfs     string `json:"obfs"`
}

func (n HysteriaNode) String() string {
	return fmt.Sprintf("{Version:%d UpMbps:%d DownMbps:%d Obfs:REDACTED}", n.Version, n.UpMbps, n.DownMbps)
}

func (n HysteriaNode) GoString() string {
	return n.String()
}

func (n *HysteriaNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type Hysteria2Node struct {
	CommonNode
	Version               int    `json:"version"`
	IgnoreClientBandwidth bool   `json:"ignore_client_bandwidth"`
	UpMbps                int    `json:"up_mbps"`
	DownMbps              int    `json:"down_mbps"`
	ObfsType              string `json:"obfs"`
	ObfsPassword          string `json:"obfs-password"`
}

func (n Hysteria2Node) String() string {
	return fmt.Sprintf("{Version:%d IgnoreClientBandwidth:%t UpMbps:%d DownMbps:%d ObfsType:REDACTED ObfsPassword:REDACTED}", n.Version, n.IgnoreClientBandwidth, n.UpMbps, n.DownMbps)
}

func (n Hysteria2Node) GoString() string {
	return n.String()
}

func (n *Hysteria2Node) GetCommonNode() *CommonNode {
	return &n.CommonNode
}
