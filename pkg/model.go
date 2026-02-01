package pkg

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

// Node types
const (
	Shadowsocks = "shadowsocks"
	Trojan      = "trojan"
	Vmess       = "vmess"
	Vless       = "vless"
	Tuic        = "tuic"
	Hysteria    = "hysteria"
	Hysteria2   = "hysteria2"
	AnyTls      = "anytls"
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	RawDNS       RawDNS
	Rules        Rules

	// origin
	VMess       *VMessNode
	Vless       *VlessNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	AnyTls      *AnyTlsNode
	Hysteria    *HysteriaNode
	Hysteria2   *Hysteria2Node
	Common      *CommonNode
}

type CommonNode struct {
	Host       string      `json:"host"`
	ServerPort int         `json:"server_port"`
	ServerName string      `json:"server_name"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
}

// Node interface for polymorphic handling
type Node interface {
	GetCommonNode() *CommonNode
}

type Route struct {
	Id          int         `json:"id"`
	Match       interface{} `json:"match"`
	Action      string      `json:"action"`
	ActionValue string      `json:"action_value"`
}
type BaseConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

// VMessNode is vmess node info
type VMessNode struct {
	CommonNode
	Tls                int             `json:"tls"`
	TlsSettings        TlsSettings     `json:"tls_settings"`
	Network            string          `json:"network"`
	NetworkSettings    json.RawMessage `json:"network_settings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
	ServerName         string          `json:"server_name"`
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
	NetworkSettings    json.RawMessage `json:"network_settings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
	ServerName         string          `json:"server_name"`
	Flow               string          `json:"flow"`
	RealityConfig      RealityConfig   `json:"-"`
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

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
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

func (n *ShadowsocksNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type TrojanNode struct {
	CommonNode
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
}

func (n *TrojanNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type TuicNode struct {
	CommonNode
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
}

func (n *TuicNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type AnyTlsNode struct {
	CommonNode
	PaddingScheme []string `json:"padding_scheme,omitempty"`
}

func (n *AnyTlsNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type HysteriaNode struct {
	CommonNode
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	Obfs     string `json:"obfs"`
}

func (n *HysteriaNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type Hysteria2Node struct {
	CommonNode
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	ObfsType                string `json:"obfs"`
	ObfsPassword            string `json:"obfs-password"`
}

func (n *Hysteria2Node) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type RawDNS struct {
	DNSMap  map[string]map[string]interface{}
	DNSJson []byte
}

type Rules struct {
	Regexp   []string
	Protocol []string
}

// User structures
type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// Helper function to convert dynamic interval types to time.Duration
func IntervalToTime(i interface{}) time.Duration {
	switch v := i.(type) {
	case int:
		return time.Duration(v) * time.Second
	case string:
		val, _ := strconv.Atoi(v)
		return time.Duration(val) * time.Second
	case float64:
		return time.Duration(v) * time.Second
	}
	return 0
}

// ProcessCommonNode handles the common node configuration like routes and DNS.
func (node *NodeInfo) ProcessCommonNode(cm *CommonNode) {
	if cm == nil {
		return
	}

	for i := range cm.Routes {
		var matchs []string
		if _, ok := cm.Routes[i].Match.(string); ok {
			matchs = strings.Split(cm.Routes[i].Match.(string), ",")
		} else if _, ok = cm.Routes[i].Match.([]string); ok {
			matchs = cm.Routes[i].Match.([]string)
		} else {
			// Handle []interface{} case if needed
			if temp, ok := cm.Routes[i].Match.([]interface{}); ok {
				matchs = make([]string, len(temp))
				for j := range temp {
					if str, ok := temp[j].(string); ok {
						matchs[j] = str
					}
				}
			}
		}
		switch cm.Routes[i].Action {
		case "block":
			for _, v := range matchs {
				if strings.HasPrefix(v, "protocol:") {
					node.Rules.Protocol = append(node.Rules.Protocol, strings.TrimPrefix(v, "protocol:"))
				} else {
					node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
				}
			}
		case "dns":
			var domains []string
			domains = append(domains, matchs...)
			if len(matchs) > 0 && matchs[0] != "main" {
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": cm.Routes[i].ActionValue,
					"domains": domains,
				}
			} else if len(matchs) > 1 {
				dns := []byte(strings.Join(matchs[1:], ""))
				node.RawDNS.DNSJson = dns
			}
		}
	}

	// set interval
	if cm.BaseConfig != nil {
		node.PushInterval = IntervalToTime(cm.BaseConfig.PushInterval)
		node.PullInterval = IntervalToTime(cm.BaseConfig.PullInterval)
	}

	node.Common = cm
	// Clear fields to save memory if needed
	cm.Routes = nil
	cm.BaseConfig = nil
}
