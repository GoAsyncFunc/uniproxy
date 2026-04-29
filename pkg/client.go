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
	"net/url"
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
	getRetryCount     = 2
	getRetryBackoff   = 10 * time.Millisecond
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
	userList         *UserListBody
	handlers         map[string]NodeHandler
}

func normalizeNodeType(nodeType string) (string, bool) {
	normalized := strings.ToLower(nodeType)
	if normalized == "v2ray" {
		return Vmess, true
	}
	switch normalized {
	case Vmess, Trojan, Shadowsocks, Hysteria, Hysteria2, Tuic, AnyTls, Vless:
		return normalized, true
	default:
		return normalized, false
	}
}

func validateConfig(c *Config) error {
	if c == nil {
		return errors.New("config is nil")
	}
	if strings.TrimSpace(c.APIHost) == "" {
		return errors.New("api host is required")
	}
	parsed, err := url.Parse(c.APIHost)
	if err != nil {
		return fmt.Errorf("invalid api host: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("api host scheme must be http or https: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("api host must include host")
	}
	if strings.TrimSpace(c.Key) == "" {
		return errors.New("api key is required")
	}
	if c.NodeID <= 0 {
		return fmt.Errorf("node id must be positive: %d", c.NodeID)
	}
	if _, ok := normalizeNodeType(c.NodeType); !ok {
		return fmt.Errorf("unsupported node type: %s", c.NodeType)
	}
	if c.APISendIP != "" && net.ParseIP(c.APISendIP) == nil {
		return fmt.Errorf("invalid api send ip: %s", c.APISendIP)
	}
	return nil
}

func NewWithError(c *Config) (*Client, error) {
	if err := validateConfig(c); err != nil {
		return nil, err
	}
	return New(c), nil
}

// New creates an API client for the panel and returns nil when config validation fails.
func New(c *Config) *Client {
	if err := validateConfig(c); err != nil {
		log.Warnf("invalid api config: %v", err)
		return nil
	}

	var client *resty.Client
	if c.APISendIP != "" {
		client = resty.NewWithLocalAddr(&net.TCPAddr{
			IP: net.ParseIP(c.APISendIP),
		})
	} else {
		client = resty.New()
		client.SetTransport(ipv4FirstTransport())
	}

	client.SetRetryCount(0)
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

	nodeType, ok := normalizeNodeType(c.NodeType)
	if !ok {
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
		userList:  &UserListBody{},
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

// CachedUserList returns a copy of the cached users.
func (c *Client) CachedUserList() []UserInfo {
	c.userMu.Lock()
	defer c.userMu.Unlock()
	if c.userList == nil {
		return nil
	}
	return cloneUserInfos(c.userList.Users)
}

func (c *Client) checkResponse(r *resty.Response, path string, err error) error {
	if err != nil {
		return NewNetworkError(fmt.Sprintf("request %s failed", path), path, err)
	}
	if r == nil {
		return NewNetworkError(fmt.Sprintf("request %s returned nil response", path), path, errors.New("nil response"))
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

func refreshETag(current *string, newETag string) {
	if newETag != "" {
		*current = newETag
	}
}

func cloneUserInfos(users []UserInfo) []UserInfo {
	if users == nil {
		return nil
	}
	return append([]UserInfo(nil), users...)
}

func validateUserList(userlist *UserListBody) error {
	if userlist == nil {
		return errors.New("user list is nil")
	}
	seen := make(map[int]struct{}, len(userlist.Users))
	for i := range userlist.Users {
		user := userlist.Users[i]
		if user.Id <= 0 {
			return fmt.Errorf("user id must be positive: %d", user.Id)
		}
		if strings.TrimSpace(user.Uuid) == "" {
			return fmt.Errorf("user uuid is required for id %d", user.Id)
		}
		if user.SpeedLimit < 0 {
			return fmt.Errorf("user speed_limit must be non-negative for id %d", user.Id)
		}
		if user.DeviceLimit < 0 {
			return fmt.Errorf("user device_limit must be non-negative for id %d", user.Id)
		}
		if _, ok := seen[user.Id]; ok {
			return fmt.Errorf("duplicate user id: %d", user.Id)
		}
		seen[user.Id] = struct{}{}
	}
	return nil
}

func validateCommonNode(cm *CommonNode) error {
	if cm == nil {
		return errors.New("common node is nil")
	}
	if cm.ServerPort <= 0 || cm.ServerPort > 65535 {
		return fmt.Errorf("server_port must be between 1 and 65535: %d", cm.ServerPort)
	}
	return nil
}

func validateTLSEnum(protocol string, value int) error {
	switch value {
	case None, Tls, Reality:
		return nil
	default:
		return fmt.Errorf("%s tls must be one of %d, %d, or %d: %d", protocol, None, Tls, Reality, value)
	}
}

func validateProtocolSpecificNode(node *NodeInfo) error {
	if node.VMess != nil {
		return validateTLSEnum(Vmess, node.VMess.Tls)
	}
	if node.Vless != nil {
		return validateTLSEnum(Vless, node.Vless.Tls)
	}
	if node.Hysteria != nil && (node.Hysteria.UpMbps < 0 || node.Hysteria.DownMbps < 0) {
		return fmt.Errorf("hysteria bandwidth must be non-negative")
	}
	if node.Hysteria2 != nil && (node.Hysteria2.UpMbps < 0 || node.Hysteria2.DownMbps < 0) {
		return fmt.Errorf("hysteria2 bandwidth must be non-negative")
	}
	return nil
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (c *Client) getWithRetry(ctx context.Context, path string, configure func(*resty.Request)) (*resty.Response, error) {
	ctx = normalizeContext(ctx)
	var r *resty.Response
	var err error
	for attempt := 0; attempt <= getRetryCount; attempt++ {
		req := c.client.R().SetContext(ctx).ForceContentType(contentTypeJSON)
		if configure != nil {
			configure(req)
		}
		r, err = req.Get(path)
		if err == nil && r != nil && r.StatusCode() < 500 {
			return r, nil
		}
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		if attempt < getRetryCount {
			select {
			case <-ctx.Done():
				return r, ctx.Err()
			case <-time.After(getRetryBackoff):
			}
		}
	}
	if err == nil && r == nil {
		err = errors.New("nil response")
	}
	return r, err
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()

	r, err := c.getWithRetry(ctx, apiConfigPath, func(req *resty.Request) {
		req.SetHeader(headerIfNoneMatch, c.nodeEtag)
	})

	if err != nil {
		return nil, NewNetworkError("request failed", apiConfigPath, err)
	}

	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err = c.checkResponse(r, apiConfigPath, nil); err != nil {
		return nil, err
	}

	if r.Body() == nil {
		return nil, NewNetworkError("received nil response body", apiConfigPath, nil)
	}

	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	newEtag := r.Header().Get(headerETag)

	if c.responseBodyHash == newBodyHash {
		refreshETag(&c.nodeEtag, newEtag)
		return nil, nil
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
	if err := validateCommonNode(cm); err != nil {
		return nil, NewParseError(fmt.Sprintf("validate %s params error", c.NodeType), err)
	}
	if err := validateProtocolSpecificNode(node); err != nil {
		return nil, NewParseError(fmt.Sprintf("validate %s params error", c.NodeType), err)
	}

	node.ProcessCommonNode(cm)

	c.responseBodyHash = newBodyHash
	refreshETag(&c.nodeEtag, newEtag)

	return node, nil
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	c.userMu.Lock()
	defer c.userMu.Unlock()

	r, err := c.getWithRetry(ctx, apiUserPath, func(req *resty.Request) {
		req.SetHeader(headerIfNoneMatch, c.userEtag)
	})

	if err != nil {
		return nil, NewNetworkError("request failed", apiUserPath, err)
	}

	if r.StatusCode() == 304 {
		if c.userList != nil {
			return cloneUserInfos(c.userList.Users), nil
		}
		return nil, nil
	}

	if err = c.checkResponse(r, apiUserPath, nil); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(r.Body())
	newHash := hex.EncodeToString(hash[:])
	newEtag := r.Header().Get(headerETag)
	if c.userBodyHash == newHash {
		refreshETag(&c.userEtag, newEtag)
		if c.userList != nil {
			return cloneUserInfos(c.userList.Users), nil
		}
		return nil, nil
	}

	userlist := &UserListBody{}
	if err := json.Unmarshal(r.Body(), userlist); err != nil {
		return nil, NewParseError("decode user list error", err)
	}
	if err := validateUserList(userlist); err != nil {
		return nil, NewParseError("validate user list error", err)
	}

	refreshETag(&c.userEtag, newEtag)
	c.userBodyHash = newHash
	c.userList = userlist

	return cloneUserInfos(userlist.Users), nil
}

func validateUserTraffic(userTraffic []UserTraffic) error {
	seen := make(map[int]struct{}, len(userTraffic))
	for i := range userTraffic {
		if userTraffic[i].UID <= 0 {
			return fmt.Errorf("user traffic uid must be positive: %d", userTraffic[i].UID)
		}
		if _, ok := seen[userTraffic[i].UID]; ok {
			return fmt.Errorf("duplicate user traffic uid: %d", userTraffic[i].UID)
		}
		seen[userTraffic[i].UID] = struct{}{}
		if userTraffic[i].Upload < 0 || userTraffic[i].Download < 0 {
			return fmt.Errorf("user traffic must be non-negative for uid %d", userTraffic[i].UID)
		}
	}
	return nil
}

func validateOnlineUsers(data map[int][]string) error {
	if data == nil {
		return errors.New("online user data is nil")
	}
	for uid, users := range data {
		if uid <= 0 {
			return fmt.Errorf("online user uid must be positive: %d", uid)
		}
		if len(users) == 0 {
			return fmt.Errorf("online user list is empty for uid %d", uid)
		}
		for _, user := range users {
			parts := strings.Split(user, "_")
			if len(parts) != 2 {
				return fmt.Errorf("invalid online user entry for uid %d: %q", uid, user)
			}
			ip := strings.TrimSpace(parts[0])
			suffix := strings.TrimSpace(parts[1])
			if parts[0] != ip || parts[1] != suffix || ip == "" || suffix == "" || net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid online user entry for uid %d: %q", uid, user)
			}
			if strings.HasPrefix(suffix, "+") || strings.HasPrefix(suffix, "-") {
				return fmt.Errorf("invalid online user entry for uid %d: %q", uid, user)
			}
			if _, err := strconv.Atoi(suffix); err != nil {
				return fmt.Errorf("invalid online user entry for uid %d: %q", uid, user)
			}
		}
	}
	return nil
}

func (c *Client) ReportUserTraffic(ctx context.Context, userTraffic []UserTraffic) error {
	if err := validateUserTraffic(userTraffic); err != nil {
		return err
	}
	if len(userTraffic) == 0 {
		return nil
	}
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		data[userTraffic[i].UID] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
	}
	r, err := c.client.R().
		SetContext(normalizeContext(ctx)).
		SetBody(data).
		ForceContentType(contentTypeJSON).
		Post(apiPushPath)

	return c.checkResponse(r, apiPushPath, err)
}

func cloneOnlineUsers(data map[int][]string) map[int][]string {
	cloned := make(map[int][]string, len(data))
	for uid, users := range data {
		cloned[uid] = append([]string(nil), users...)
	}
	return cloned
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data map[int][]string) error {
	if err := validateOnlineUsers(data); err != nil {
		return err
	}
	r, err := c.client.R().
		SetContext(normalizeContext(ctx)).
		SetBody(cloneOnlineUsers(data)).
		ForceContentType(contentTypeJSON).
		Post(apiAlivePath)

	return c.checkResponse(r, apiAlivePath, err)
}

func (c *Client) GetAliveList(ctx context.Context) (map[int]int, error) {
	r, err := c.getWithRetry(ctx, apiAliveListPath, nil)

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

	if resp.Alive == nil {
		return map[int]int{}, nil
	}
	for uid, count := range resp.Alive {
		if uid <= 0 {
			return nil, NewParseError("decode alive list error", fmt.Errorf("alive uid must be positive: %d", uid))
		}
		if count < 0 {
			return nil, NewParseError("decode alive list error", fmt.Errorf("alive count must be non-negative for uid %d", uid))
		}
	}

	return resp.Alive, nil
}
