package pkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	resty "github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

// Config  api config
type Config struct {
	APIHost   string
	APISendIP string
	NodeID    int
	Key       string
	NodeType  string
	Timeout   int // seconds
	Debug     bool
}

const (
	apiConfigPath     = "/api/v1/server/UniProxy/config"
	apiUserPath       = "/api/v1/server/UniProxy/user"
	apiPushPath       = "/api/v1/server/UniProxy/push"
	apiAlivePath      = "/api/v1/server/UniProxy/alive"
	headerIfNoneMatch = "If-None-Match"
	headerETag        = "ETag"
	contentTypeJSON   = "application/json"
	headerContentType = "Content-Type"
)

// Client APIClient create a api client to the panel.
type Client struct {
	client           *resty.Client
	APIHost          string
	APISendIP        string
	Token            string
	NodeType         string
	NodeId           int
	mu               sync.RWMutex // Protects mutable state
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
}

// New creat a api instance
func New(c *Config) *Client {
	var client *resty.Client
	if c.APISendIP != "" {
		client = resty.NewWithLocalAddr(&net.TCPAddr{
			IP: net.ParseIP(c.APISendIP),
		})
	} else {
		client = resty.New()
	}

	client.SetRetryCount(3)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}

	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			log.Error(v.Err)
		}
	})

	client.SetBaseURL(c.APIHost)

	// Check node type and normalize
	nodeType := strings.ToLower(c.NodeType)
	switch nodeType {
	case "v2ray":
		nodeType = "vmess"
	case "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "anytls", "vless":
	default:
		// Just log warning, allow proceeding if it's a new type
		log.Warnf("Unknown Node type: %s", nodeType)
	}

	client.SetQueryParams(map[string]string{
		"node_type": nodeType,
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})

	if c.Debug {
		client.SetDebug(true)
	}

	return &Client{
		client:    client,
		Token:     c.Key,
		APIHost:   c.APIHost,
		APISendIP: c.APISendIP,
		NodeType:  nodeType,
		NodeId:    c.NodeID,
		UserList:  &UserListBody{},
		AliveMap:  &AliveMap{},
	}
}

// Debug set the client debug for client
func (c *Client) Debug(enable bool) {
	c.client.SetDebug(enable)
}

func (c *Client) checkResponse(r *resty.Response, path string, err error) error {
	if err != nil {
		return fmt.Errorf("request %s failed: %w", path, err)
	}
	if r.StatusCode() >= 400 {
		return fmt.Errorf("request %s failed with status: %d, body: %s", path, r.StatusCode(), string(r.Body()))
	}
	return nil
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	c.mu.RLock()
	currentEtag := c.nodeEtag
	currentBodyHash := c.responseBodyHash
	c.mu.RUnlock()

	r, err := c.client.
		R().
		SetContext(ctx).
		SetHeader(headerIfNoneMatch, currentEtag).
		ForceContentType(contentTypeJSON).
		Get(apiConfigPath)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if r.StatusCode() == 304 {
		return nil, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])

	if currentBodyHash == newBodyHash {
		return nil, nil
	}

	// Lock for writing updates
	c.mu.Lock()
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get(headerETag)
	c.mu.Unlock()

	if err = c.checkResponse(r, apiConfigPath, err); err != nil {
		return nil, err
	}

	if r == nil || r.Body() == nil {
		return nil, fmt.Errorf("received nil response")
	}

	node = &NodeInfo{
		Id:   c.NodeId,
		Type: c.NodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}

	var cm *CommonNode
	switch c.NodeType {
	case "vmess":
		node.VMess, cm, err = parseNodeWithCommon[VMessNode](r.Body())
		if err == nil {
			// Handle legacy field mapping for VMess
			if len(node.VMess.NetworkSettingsBack) > 0 {
				node.VMess.NetworkSettings = node.VMess.NetworkSettingsBack
				node.VMess.NetworkSettingsBack = nil
			}
			if node.VMess.TlsSettingsBack != nil {
				node.VMess.TlsSettings = *node.VMess.TlsSettingsBack
				node.VMess.TlsSettingsBack = nil
			}
			node.Security = node.VMess.Tls
		}
	case "vless":
		node.Vless, cm, err = parseNodeWithCommon[VlessNode](r.Body())
		if err == nil {
			// Handle legacy field mapping for VLESS
			if len(node.Vless.NetworkSettingsBack) > 0 {
				node.Vless.NetworkSettings = node.Vless.NetworkSettingsBack
				node.Vless.NetworkSettingsBack = nil
			}
			if node.Vless.TlsSettingsBack != nil {
				node.Vless.TlsSettings = *node.Vless.TlsSettingsBack
				node.Vless.TlsSettingsBack = nil
			}
			node.Security = node.Vless.Tls
		}
	case "shadowsocks":
		node.Shadowsocks, cm, err = parseNodeWithCommon[ShadowsocksNode](r.Body())
		if err == nil {
			node.Security = None
		}
	case "trojan":
		node.Trojan, cm, err = parseNodeWithCommon[TrojanNode](r.Body())
		if err == nil {
			node.Security = Tls
		}
	case "tuic":
		node.Tuic, cm, err = parseNodeWithCommon[TuicNode](r.Body())
		if err == nil {
			node.Security = Tls
		}
	case "anytls":
		node.AnyTls, cm, err = parseNodeWithCommon[AnyTlsNode](r.Body())
		if err == nil {
			node.Security = Tls
		}
	case "hysteria":
		node.Hysteria, cm, err = parseNodeWithCommon[HysteriaNode](r.Body())
		if err == nil {
			node.Security = Tls
		}
	case "hysteria2":
		node.Hysteria2, cm, err = parseNodeWithCommon[Hysteria2Node](r.Body())
		if err == nil {
			node.Security = Tls
		}
	}

	if err != nil {
		return nil, fmt.Errorf("decode %s params error: %w", c.NodeType, err)
	}

	// parse rules and dns
	if cm != nil {
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

	return node, nil
}

// GetUserList will pull user from v2board
// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	c.mu.RLock()
	currentEtag := c.userEtag
	c.mu.RUnlock()

	r, err := c.client.R().
		SetContext(ctx).
		SetHeader(headerIfNoneMatch, currentEtag).
		ForceContentType(contentTypeJSON).
		Get(apiUserPath)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if r.StatusCode() == 304 {
		c.mu.RLock()
		defer c.mu.RUnlock()
		if c.UserList != nil {
			return c.UserList.Users, nil
		}
		return nil, nil // Should not happen if etag matches, but handle gracefully
	}

	if err = c.checkResponse(r, apiUserPath, err); err != nil {
		return nil, err
	}

	userlist := &UserListBody{}
	if err := json.Unmarshal(r.Body(), userlist); err != nil {
		return nil, fmt.Errorf("decode user list error: %w", err)
	}

	c.mu.Lock()
	c.userEtag = r.Header().Get(headerETag)
	c.UserList = userlist
	c.mu.Unlock()

	return userlist.Users, nil
}

// Upload/Download are type int64 in UserTraffic struct in model.go
func (c *Client) ReportUserTraffic(ctx context.Context, userTraffic []UserTraffic) error {
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		data[userTraffic[i].UID] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
	}
	r, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType(contentTypeJSON).
		Post(apiPushPath)

	return c.checkResponse(r, apiPushPath, err)
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data map[int][]string) error {
	r, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType(contentTypeJSON).
		Post(apiAlivePath)

	return c.checkResponse(r, apiAlivePath, err)
}

// Helper generic function to parsing node
type commonNodeGetter interface {
	GetCommonNode() *CommonNode
}

func parseNodeWithCommon[T any](data []byte) (*T, *CommonNode, error) {
	var node T
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, nil, err
	}
	// Use reflection to extract CommonNode field since Go generics don't support struct field access directly without interface
	// Ideally structs should implement an interface, but for now we assume structure match.
	// Actually, since we are inside the package, we know the structure.
	// But we need to return *CommonNode.
	// Let's use a simpler approach: define an interface or just use reflection here as it happens once per config update (rare).
	// Better yet, since all node types embed CommonNode, we can cast if we define an interface.

	// A faster way without reflection for known types:
	// We already reformatted the switch case to handle this.
	// But wait, I need to extract CommonNode from T.

	// Let's rely on the caller to do the assignment or use reflection carefully.
	// Since all node types have CommonNode as first field (embedded), we can unsafe pointer cast or reflection.
	// Safe way for now: return T and let caller handle.
	// But the caller block was designed to be generic.

	// Actually, let's keep it simple. We will return the Typed struct and the CommonNode.
	// Since we can't easily interface the field access generically in Go 1.20 without methods.

	v := any(&node)
	var cm *CommonNode

	switch t := v.(type) {
	case *VMessNode:
		cm = &t.CommonNode
	case *VlessNode:
		cm = &t.CommonNode
	case *ShadowsocksNode:
		cm = &t.CommonNode
	case *TrojanNode:
		cm = &t.CommonNode
	case *TuicNode:
		cm = &t.CommonNode
	case *AnyTlsNode:
		cm = &t.CommonNode
	case *HysteriaNode:
		cm = &t.CommonNode
	case *Hysteria2Node:
		cm = &t.CommonNode
	}

	return &node, cm, nil
}
