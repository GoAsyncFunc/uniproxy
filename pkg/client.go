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
	apiConfigPath        = "/api/v1/server/UniProxy/config"
	apiUserPath          = "/api/v1/server/UniProxy/user"
	apiPushPath          = "/api/v1/server/UniProxy/push"
	apiAlivePath         = "/api/v1/server/UniProxy/alive"
	apiAliveListPath     = "/api/v1/server/UniProxy/alivelist"
	headerIfNoneMatch    = "If-None-Match"
	headerETag           = "ETag"
	headerAuthorization  = "Authorization"
	contentTypeJSON      = "application/json"
	getRetryCount        = 2
	getRetryBackoff      = 10 * time.Millisecond
	maxResponseBodyBytes = 8 * 1024 * 1024
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

type redactedRestyClient struct {
	*resty.Client
}

func (c redactedRestyClient) String() string {
	return "REDACTED"
}

func (c redactedRestyClient) GoString() string {
	return "REDACTED"
}

type sensitiveToken struct {
	value string
}

func (t *sensitiveToken) raw() string {
	if t == nil {
		return ""
	}
	return t.value
}

func (t *sensitiveToken) String() string {
	return "REDACTED"
}

func (t *sensitiveToken) GoString() string {
	return "REDACTED"
}

type clientConfig struct {
	apiHost   string
	apiSendIP string
	token     *sensitiveToken
	nodeType  string
	nodeID    int
}

// Client APIClient create a api client to the panel.
type Client struct {
	client *redactedRestyClient
	config clientConfig

	// Deprecated: this field is informational; mutating it does not affect client behavior.
	APIHost string
	// Deprecated: this field is informational; mutating it does not affect client behavior.
	APISendIP string
	// Deprecated: this field is informational; mutating it does not affect client behavior.
	Token string
	// Deprecated: this field is informational; mutating it does not affect client behavior.
	NodeType string
	// Deprecated: this field is informational; mutating it does not affect client behavior.
	NodeId int

	nodeMu           sync.Mutex
	userMu           sync.Mutex
	nodeRefreshMu    sync.Mutex
	userRefreshMu    sync.Mutex
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	userBodyHash     string
	userList         *UserListBody
	handlers         map[string]NodeHandler
}

func (c *Client) String() string {
	if c == nil {
		return "<nil>"
	}
	return fmt.Sprintf("&{APIHost:%s APISendIP:%s Token:REDACTED NodeType:%s NodeId:%d}", redactURL(c.APIHost), c.APISendIP, c.NodeType, c.NodeId)
}

func (c *Client) GoString() string {
	if c == nil {
		return "(*pkg.Client)(nil)"
	}
	return fmt.Sprintf("&pkg.Client{APIHost:%q, APISendIP:%q, Token:REDACTED, NodeType:%q, NodeId:%d}", redactURL(c.APIHost), c.APISendIP, c.NodeType, c.NodeId)
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
	client.SetResponseBodyLimit(maxResponseBodyBytes)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}

	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			log.Error(sanitizeError(v.Err))
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
		log.Warn("debug logging is disabled because legacy query authentication can expose API tokens")
	}

	return &Client{
		client: &redactedRestyClient{Client: client},
		config: clientConfig{
			apiHost:   c.APIHost,
			apiSendIP: c.APISendIP,
			token:     &sensitiveToken{value: c.Key},
			nodeType:  nodeType,
			nodeID:    c.NodeID,
		},
		Token:     "REDACTED",
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

// Debug is disabled because legacy query authentication can expose API tokens.
// Deprecated: configure application-level sanitized logging instead.
func (c *Client) Debug(enable bool) {
	if enable {
		log.Warn("debug logging is disabled because legacy query authentication can expose API tokens")
	}
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

func newRequestError(path string, err error) *APIError {
	if errors.Is(err, resty.ErrResponseBodyTooLarge) {
		return NewNetworkError("response body too large", path, err)
	}
	return NewNetworkError(fmt.Sprintf("request %s failed", path), path, err)
}

func (c *Client) checkResponse(r *resty.Response, path string, err error) error {
	if err != nil {
		return newRequestError(path, err)
	}
	if r == nil {
		return NewNetworkError(fmt.Sprintf("request %s returned nil response", path), path, errors.New("nil response"))
	}
	if r.StatusCode() >= 400 {
		message := "response body too large"
		if len(r.Body()) <= maxResponseBodyBytes {
			message = sanitizeAPIErrorMessage(string(r.Body()))
		}
		return NewAPIErrorFromStatusCode(
			r.StatusCode(),
			message,
			path,
			nil,
		)
	}
	return nil
}

func checkResponseBodySize(path string, body []byte) error {
	if len(body) <= maxResponseBodyBytes {
		return nil
	}
	return NewParseError("response body too large", fmt.Errorf("%s response body is %d bytes, limit is %d", path, len(body), maxResponseBodyBytes))
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

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (c *Client) newRequest(ctx context.Context) *resty.Request {
	return c.client.R().
		SetContext(normalizeContext(ctx)).
		SetHeader(headerAuthorization, "Bearer "+c.config.token.raw()).
		ForceContentType(contentTypeJSON)
}

func (c *Client) getWithRetry(ctx context.Context, path string, configure func(*resty.Request)) (*resty.Response, error) {
	ctx = normalizeContext(ctx)
	var r *resty.Response
	var err error
	for attempt := 0; attempt <= getRetryCount; attempt++ {
		req := c.newRequest(ctx)
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
	c.nodeRefreshMu.Lock()
	defer c.nodeRefreshMu.Unlock()

	c.nodeMu.Lock()
	nodeEtag := c.nodeEtag
	c.nodeMu.Unlock()

	r, err := c.getWithRetry(ctx, apiConfigPath, func(req *resty.Request) {
		req.SetHeader(headerIfNoneMatch, nodeEtag)
	})

	if err != nil {
		return nil, newRequestError(apiConfigPath, err)
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
	if err := checkResponseBodySize(apiConfigPath, r.Body()); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	newEtag := r.Header().Get(headerETag)

	c.nodeMu.Lock()
	if c.responseBodyHash == newBodyHash {
		refreshETag(&c.nodeEtag, newEtag)
		c.nodeMu.Unlock()
		return nil, nil
	}
	c.nodeMu.Unlock()

	node = &NodeInfo{
		Id:   c.config.nodeID,
		Type: c.config.nodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}

	var cm *CommonNode
	if handler, ok := c.handlers[c.config.nodeType]; ok {
		cm, err = handler.ParseConfig(node, r.Body())
	} else {
		return nil, NewParseError(fmt.Sprintf("unsupported node type: %s", c.config.nodeType), nil)
	}

	if err != nil {
		return nil, NewParseError(fmt.Sprintf("decode %s params error", c.config.nodeType), err)
	}
	if err := validateCommonNode(cm); err != nil {
		return nil, NewParseError(fmt.Sprintf("validate %s params error", c.config.nodeType), err)
	}
	if err := validateProtocolSpecificNode(node); err != nil {
		return nil, NewParseError(fmt.Sprintf("validate %s params error", c.config.nodeType), err)
	}

	node.ProcessCommonNode(cm)

	c.nodeMu.Lock()
	c.responseBodyHash = newBodyHash
	refreshETag(&c.nodeEtag, newEtag)
	c.nodeMu.Unlock()

	return node, nil
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	c.userRefreshMu.Lock()
	defer c.userRefreshMu.Unlock()

	c.userMu.Lock()
	userEtag := c.userEtag
	cachedUsers := []UserInfo(nil)
	if c.userList != nil {
		cachedUsers = cloneUserInfos(c.userList.Users)
	}
	c.userMu.Unlock()

	r, err := c.getWithRetry(ctx, apiUserPath, func(req *resty.Request) {
		req.SetHeader(headerIfNoneMatch, userEtag)
	})

	if err != nil {
		return nil, newRequestError(apiUserPath, err)
	}

	if r.StatusCode() == 304 {
		return cachedUsers, nil
	}

	if err = c.checkResponse(r, apiUserPath, nil); err != nil {
		return nil, err
	}
	if err := checkResponseBodySize(apiUserPath, r.Body()); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(r.Body())
	newHash := hex.EncodeToString(hash[:])
	newEtag := r.Header().Get(headerETag)

	c.userMu.Lock()
	if c.userBodyHash == newHash {
		refreshETag(&c.userEtag, newEtag)
		cachedUsers = nil
		if c.userList != nil {
			cachedUsers = cloneUserInfos(c.userList.Users)
		}
		c.userMu.Unlock()
		return cachedUsers, nil
	}
	c.userMu.Unlock()

	userlist := &UserListBody{}
	if err := json.Unmarshal(r.Body(), userlist); err != nil {
		return nil, NewParseError("decode user list error", err)
	}
	if err := validateUserList(userlist); err != nil {
		return nil, NewParseError("validate user list error", err)
	}

	c.userMu.Lock()
	refreshETag(&c.userEtag, newEtag)
	c.userBodyHash = newHash
	c.userList = userlist
	c.userMu.Unlock()

	return cloneUserInfos(userlist.Users), nil
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
	r, err := c.newRequest(ctx).
		SetBody(data).
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
	r, err := c.newRequest(ctx).
		SetBody(cloneOnlineUsers(data)).
		Post(apiAlivePath)

	return c.checkResponse(r, apiAlivePath, err)
}

func (c *Client) GetAliveList(ctx context.Context) (map[int]int, error) {
	r, err := c.getWithRetry(ctx, apiAliveListPath, nil)

	if err != nil {
		return nil, newRequestError(apiAliveListPath, err)
	}

	if err = c.checkResponse(r, apiAliveListPath, nil); err != nil {
		return nil, err
	}
	if err := checkResponseBodySize(apiAliveListPath, r.Body()); err != nil {
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
