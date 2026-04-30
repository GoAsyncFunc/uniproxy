package pkg

import (
	"encoding/json"
	"fmt"
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

func (n NodeInfo) String() string {
	return fmt.Sprintf("{Id:%d Type:%s Security:%d Routes:%d RawDNS:REDACTED VMess:%t Vless:%t Shadowsocks:%t Trojan:%t Tuic:%t AnyTls:%t Hysteria:%t Hysteria2:%t}", n.Id, n.Type, n.Security, len(n.Routes), n.VMess != nil, n.Vless != nil, n.Shadowsocks != nil, n.Trojan != nil, n.Tuic != nil, n.AnyTls != nil, n.Hysteria != nil, n.Hysteria2 != nil)
}

func (n NodeInfo) GoString() string {
	return n.String()
}

type CommonNode struct {
	Host       string      `json:"host"`
	ServerPort int         `json:"server_port"`
	ServerName string      `json:"server_name"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
}

func (n CommonNode) String() string {
	return fmt.Sprintf("{Host:REDACTED ServerPort:%d ServerName:REDACTED Routes:%d BaseConfig:%t}", n.ServerPort, len(n.Routes), n.BaseConfig != nil)
}

func (n CommonNode) GoString() string {
	return n.String()
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

func (r Route) String() string {
	return fmt.Sprintf("{Id:%d Action:REDACTED Match:%d ActionValue:REDACTED}", r.Id, len(r.Matches()))
}

func (r Route) GoString() string {
	return r.String()
}

func (r Route) Matches() []string {
	return NormalizeRouteMatch(r.Match)
}

func (r Route) DNSMatches() []string {
	match, ok := r.Match.(string)
	if !ok {
		return r.Matches()
	}
	prefix, value, found := strings.Cut(match, ",")
	if !found || strings.TrimSpace(prefix) != "main" {
		return r.Matches()
	}
	return []string{"main", strings.TrimSpace(value)}
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

func (c BaseConfig) String() string {
	return "{PushInterval:REDACTED PullInterval:REDACTED}"
}

func (c BaseConfig) GoString() string {
	return c.String()
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

type RawDNS struct {
	DNSMap  map[string]map[string]interface{}
	DNSJson []byte
}

func (d RawDNS) String() string {
	return fmt.Sprintf("{DNSMap:%d DNSJson:REDACTED}", len(d.DNSMap))
}

func (d RawDNS) GoString() string {
	return d.String()
}

type Rules struct {
	Regexp   []string
	Protocol []string
}

func (r Rules) String() string {
	return fmt.Sprintf("{Regexp:%d REDACTED Protocol:%d REDACTED}", len(r.Regexp), len(r.Protocol))
}

func (r Rules) GoString() string {
	return r.String()
}

// User structures
type OnlineUser struct {
	UID int
	IP  string
}

func (u OnlineUser) String() string {
	if u.UID == 0 {
		return "{IP:REDACTED}"
	}
	return fmt.Sprintf("{UID:%d IP:REDACTED}", u.UID)
}

func (u OnlineUser) GoString() string {
	return u.String()
}

type UserInfo struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

func (u UserInfo) String() string {
	return fmt.Sprintf("{Id:%d Uuid:REDACTED SpeedLimit:%d DeviceLimit:%d}", u.Id, u.SpeedLimit, u.DeviceLimit)
}

func (u UserInfo) GoString() string {
	return u.String()
}

type UserListBody struct {
	Users []UserInfo `json:"users"`
}

func (u UserListBody) String() string {
	return fmt.Sprintf("{Users:%d REDACTED}", len(u.Users))
}

func (u UserListBody) GoString() string {
	return u.String()
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

func intervalSeconds(value int) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}

// Helper function to convert dynamic interval types to time.Duration
func IntervalToTime(i interface{}) time.Duration {
	switch v := i.(type) {
	case int:
		return intervalSeconds(v)
	case string:
		val, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			log.Warnf("IntervalToTime: invalid string value length=%d", len(v))
			return 0
		}
		return intervalSeconds(val)
	case float64:
		return intervalSeconds(int(v))
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
		matches := cm.Routes[i].Matches()
		switch cm.Routes[i].Action {
		case RouteActionBlock:
			domains, protocols := SplitBlockRouteMatches(matches)
			for _, v := range domains {
				node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
			}
			node.Rules.Protocol = append(node.Rules.Protocol, protocols...)
		case RouteActionDNS:
			matches = cm.Routes[i].DNSMatches()
			var domains []string
			domains = append(domains, matches...)
			if len(matches) > 0 && matches[0] != "main" {
				if node.RawDNS.DNSMap == nil {
					node.RawDNS.DNSMap = make(map[string]map[string]interface{})
				}
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": cm.Routes[i].ActionValue,
					"domains": domains,
				}
			} else if len(matches) > 1 {
				dns := []byte(strings.Join(matches[1:], ""))
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
}
