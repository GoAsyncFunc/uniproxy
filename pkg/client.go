package pkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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

// Client APIClient create a api client to the panel.
type Client struct {
	client           *resty.Client
	APIHost          string
	APISendIP        string
	Token            string
	NodeType         string
	NodeId           int
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

func (c *Client) GetNodeInfo() (node *NodeInfo, err error) {
	const path = "/api/v1/server/UniProxy/config"
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if r.StatusCode() == 304 {
		return nil, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	if err = c.checkResponse(r, path, err); err != nil {
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
		rsp := &VMessNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode vmess params error: %s", err)
		}
		if len(rsp.NetworkSettingsBack) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsBack
			rsp.NetworkSettingsBack = nil
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.VMess = rsp
		node.Security = node.VMess.Tls
	case "vless":
		rsp := &VlessNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode vless params error: %s", err)
		}
		if len(rsp.NetworkSettingsBack) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsBack
			rsp.NetworkSettingsBack = nil
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.Vless = rsp
		node.Security = node.Vless.Tls
	case "shadowsocks":
		rsp := &ShadowsocksNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode shadowsocks params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Shadowsocks = rsp
		node.Security = None
	case "trojan":
		rsp := &TrojanNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode trojan params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Trojan = rsp
		node.Security = Tls
	case "tuic":
		rsp := &TuicNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode tuic params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Tuic = rsp
		node.Security = Tls
	case "anytls":
		rsp := &AnyTlsNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode anytls params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.AnyTls = rsp
		node.Security = Tls
	case "hysteria":
		rsp := &HysteriaNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria = rsp
		node.Security = Tls
	case "hysteria2":
		rsp := &Hysteria2Node{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria2 params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria2 = rsp
		node.Security = Tls
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
func (c *Client) GetUserList() ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	r, err := c.client.R().
		SetHeader("If-None-Match", c.userEtag).
		ForceContentType("application/json").
		Get(path)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if r.StatusCode() == 304 {
		return c.UserList.Users, nil
	}

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	userlist := &UserListBody{}
	// Fallback to standard JSON since we don't assume msgpack support in this environment yet
	// If the server returns application/json, this works.
	if err := json.Unmarshal(r.Body(), userlist); err != nil {
		return nil, fmt.Errorf("decode user list error: %w", err)
	}

	c.userEtag = r.Header().Get("ETag")
	c.UserList = userlist
	return userlist.Users, nil
}

// Upload/Download are type int64 in UserTraffic struct in model.go
func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		data[userTraffic[i].UID] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
	}
	const path = "/api/v1/server/UniProxy/push"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	return c.checkResponse(r, path, err)
}

func (c *Client) ReportNodeOnlineUsers(data map[int][]string) error {
	const path = "/api/v1/server/UniProxy/alive"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	return c.checkResponse(r, path, err)
}
