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
	handlers         map[string]NodeHandler
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
		handlers: map[string]NodeHandler{
			Shadowsocks: &ShadowsocksHandler{},
			Vmess:       &VMessHandler{},
			Vless:       &VlessHandler{},
			Trojan:      &TrojanHandler{},
			Tuic:        &TuicHandler{},
			AnyTls:      &AnyTlsHandler{},
			Hysteria:    &HysteriaHandler{},
			Hysteria2:   &Hysteria2Handler{},
		},
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
	if handler, ok := c.handlers[c.NodeType]; ok {
		cm, err = handler.ParseConfig(node, r.Body())
	} else {
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("decode %s params error: %w", c.NodeType, err)
	}

	// parse rules and dns
	// parse rules and dns
	node.ProcessCommonNode(cm)

	return node, nil
}

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
