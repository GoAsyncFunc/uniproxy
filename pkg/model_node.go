package pkg

import (
	"encoding/json"
	"fmt"
	"strconv"
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

type TlsSettings struct {
	ServerName  string `json:"server_name"`
	Dest        string `json:"dest"`
	ServerPort  string `json:"server_port"`
	ShortId     string `json:"short_id"`
	PrivateKey  string `json:"private_key"`
	Mldsa65Seed string `json:"mldsa65Seed"`
	Xver        uint64 `json:"xver,string"`
}

// UnmarshalJSON accepts the numeric and string forms emitted by panel editors.
// Missing or null xver means no PROXY protocol (0).
func (t *TlsSettings) UnmarshalJSON(data []byte) error {
	type alias TlsSettings
	var decoded struct {
		alias
		Xver json.RawMessage `json:"xver"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var xver uint64
	if len(decoded.Xver) > 0 && string(decoded.Xver) != "null" {
		value := decoded.Xver
		if value[0] == '"' {
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return fmt.Errorf("invalid xver")
			}
			value = []byte(text)
		}
		var err error
		xver, err = strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			return fmt.Errorf("xver must be an integer between 0 and 2")
		}
	}
	if xver > 2 {
		return fmt.Errorf("xver must be an integer between 0 and 2")
	}
	decoded.alias.Xver = xver
	*t = TlsSettings(decoded.alias)
	return nil
}

func (t TlsSettings) String() string {
	return "{ServerName:REDACTED Dest:REDACTED ServerPort:REDACTED ShortId:REDACTED PrivateKey:REDACTED Mldsa65Seed:REDACTED Xver:REDACTED}"
}

func (t TlsSettings) GoString() string {
	return t.String()
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

func (e EncSettings) String() string {
	return "{Mode:REDACTED Ticket:REDACTED ServerPadding:REDACTED PrivateKey:REDACTED}"
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
