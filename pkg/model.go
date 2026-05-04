package pkg

import (
	"fmt"
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
