package pkg

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
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
	Routes       []Route

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

const (
	RouteActionBlock      = "block"
	RouteActionBlockIP    = "block_ip"
	RouteActionBlockPort  = "block_port"
	RouteActionProtocol   = "protocol"
	RouteActionDNS        = "dns"
	RouteActionRoute      = "route"
	RouteActionRouteIP    = "route_ip"
	RouteActionDefaultOut = "default_out"
)

type Route struct {
	Id          int         `json:"id"`
	Match       interface{} `json:"match"`
	Action      string      `json:"action"`
	ActionValue string      `json:"action_value"`
}

func (r Route) Matches() []string {
	return NormalizeRouteMatch(r.Match)
}

func IsBlockRouteAction(action string) bool {
	switch action {
	case RouteActionBlock, RouteActionBlockIP, RouteActionBlockPort, RouteActionProtocol:
		return true
	default:
		return false
	}
}

func IsCustomRouteAction(action string) bool {
	switch action {
	case RouteActionRoute, RouteActionRouteIP:
		return true
	default:
		return false
	}
}

func IsDefaultOutboundRouteAction(action string) bool {
	return action == RouteActionDefaultOut
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
	NetworkSettings    json.RawMessage `json:"networkSettings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
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
	Version  int    `json:"version"`
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	Obfs     string `json:"obfs"`
}

func (n *HysteriaNode) GetCommonNode() *CommonNode {
	return &n.CommonNode
}

type Hysteria2Node struct {
	CommonNode
	Version               int    `json:"version"`
	IgnoreClientBandwidth bool   `json:"ignore_client_bandwidth"`
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
		val, err := strconv.Atoi(v)
		if err != nil {
			log.Warnf("IntervalToTime: invalid string value %q: %v", v, err)
			return 0
		}
		return time.Duration(val) * time.Second
	case float64:
		return time.Duration(v) * time.Second
	}
	return 0
}

func NormalizeRouteMatch(match interface{}) []string {
	var raw []string
	switch v := match.(type) {
	case string:
		raw = strings.Split(v, ",")
	case []string:
		raw = v
	case []interface{}:
		raw = make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				raw = append(raw, str)
			}
		}
	}
	return TrimRouteValues(raw)
}

func TrimRouteValues(values []string) []string {
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			trimmed = append(trimmed, value)
		}
	}
	return trimmed
}

func SplitBlockRouteMatches(matches []string) ([]string, []string) {
	domains := make([]string, 0, len(matches))
	protocols := []string{}
	for _, match := range matches {
		match = strings.TrimSpace(match)
		if match == "" {
			continue
		}
		if protocol, ok := strings.CutPrefix(match, "protocol:"); ok {
			protocol = strings.TrimSpace(protocol)
			if protocol != "" {
				protocols = append(protocols, protocol)
			}
		} else {
			domains = append(domains, match)
		}
	}
	return domains, protocols
}

// ProcessCommonNode handles the common node configuration like routes and DNS.
func (node *NodeInfo) ProcessCommonNode(cm *CommonNode) {
	if cm == nil {
		return
	}

	node.Routes = append([]Route(nil), cm.Routes...)
	for i := range cm.Routes {
		matchs := cm.Routes[i].Matches()
		switch cm.Routes[i].Action {
		case RouteActionBlock:
			domains, protocols := SplitBlockRouteMatches(matchs)
			for _, v := range domains {
				node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
			}
			node.Rules.Protocol = append(node.Rules.Protocol, protocols...)
		case RouteActionDNS:
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
