package pkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	apiAliveListPath  = "/api/v1/server/UniProxy/alivelist"
	headerIfNoneMatch = "If-None-Match"
	headerETag        = "ETag"
	contentTypeJSON   = "application/json"
)

func ipv4FirstTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, "tcp4", address)
		if err == nil {
			return conn, nil
		}
		return dialer.DialContext(ctx, network, address)
	}
	return transport
}

// Client APIClient create a api client to the panel.
type Client struct {
	client           *resty.Client
	APIHost          string
	APISendIP        string
	Token            string
	NodeType         string
	NodeId           int
	nodeMu           sync.Mutex
	userMu           sync.Mutex
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	userBodyHash     string
	UserList         *UserListBody
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
		client.SetTransport(ipv4FirstTransport())
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
		return NewNetworkError(fmt.Sprintf("request %s failed", path), path, err)
	}
	if r.StatusCode() >= 400 {
		return NewAPIErrorFromStatusCode(
			r.StatusCode(),
			string(r.Body()),
			path,
			nil,
		)
	}
	return nil
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()

	r, err := c.client.
		R().
		SetContext(ctx).
		SetHeader(headerIfNoneMatch, c.nodeEtag).
		ForceContentType(contentTypeJSON).
		Get(apiConfigPath)

	if err != nil {
		return nil, NewNetworkError("request failed", apiConfigPath, err)
	}

	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err = c.checkResponse(r, apiConfigPath, nil); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])

	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}

	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get(headerETag)

	if r.Body() == nil {
		return nil, NewNetworkError("received nil response body", apiConfigPath, nil)
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
		return nil, NewParseError(fmt.Sprintf("unsupported node type: %s", c.NodeType), nil)
	}

	if err != nil {
		return nil, NewParseError(fmt.Sprintf("decode %s params error", c.NodeType), err)
	}

	node.ProcessCommonNode(cm)

	return node, nil
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	c.userMu.Lock()
	defer c.userMu.Unlock()

	r, err := c.client.R().
		SetContext(ctx).
		SetHeader(headerIfNoneMatch, c.userEtag).
		ForceContentType(contentTypeJSON).
		Get(apiUserPath)

	if err != nil {
		return nil, NewNetworkError("request failed", apiUserPath, err)
	}

	if r.StatusCode() == 304 {
		if c.UserList != nil {
			return c.UserList.Users, nil
		}
		return nil, nil
	}

	if err = c.checkResponse(r, apiUserPath, nil); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(r.Body())
	newHash := hex.EncodeToString(hash[:])
	if c.userBodyHash == newHash {
		if c.UserList != nil {
			return c.UserList.Users, nil
		}
		return nil, nil
	}

	userlist := &UserListBody{}
	if err := json.Unmarshal(r.Body(), userlist); err != nil {
		return nil, NewParseError("decode user list error", err)
	}

	c.userEtag = r.Header().Get(headerETag)
	c.userBodyHash = newHash
	c.UserList = userlist

	return userlist.Users, nil
}

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

func (c *Client) GetAliveList(ctx context.Context) (map[int]int, error) {
	r, err := c.client.R().
		SetContext(ctx).
		ForceContentType(contentTypeJSON).
		Get(apiAliveListPath)

	if err != nil {
		return nil, NewNetworkError("request failed", apiAliveListPath, err)
	}

	if err = c.checkResponse(r, apiAliveListPath, nil); err != nil {
		return nil, err
	}

	var resp struct {
		Alive map[int]int `json:"alive"`
	}
	if err := json.Unmarshal(r.Body(), &resp); err != nil {
		return nil, NewParseError("decode alive list error", err)
	}

	return resp.Alive, nil
}
