package pkg

import (
	"fmt"
	"strings"
)

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
