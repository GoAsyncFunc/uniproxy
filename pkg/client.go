package pkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
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
	contentTypeJSON      = "application/json"
	getRetryCount        = 2
	getRetryBackoff      = 100 * time.Millisecond
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

type clientConfig struct {
	apiHost   string
	apiSendIP string
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
	nodeRefresh      chan struct{}
	userRefresh      chan struct{}
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
	client.SetRedirectPolicy(resty.RedirectPolicyFunc(func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}))
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
		log.Warn("request debug logging is disabled because it can expose authentication credentials and tokens")
	}

	return &Client{
		client: &redactedRestyClient{Client: client},
		config: clientConfig{
			apiHost:   c.APIHost,
			apiSendIP: c.APISendIP,
			nodeType:  nodeType,
			nodeID:    c.NodeID,
		},
		Token:       "REDACTED",
		APIHost:     c.APIHost,
		APISendIP:   c.APISendIP,
		NodeType:    nodeType,
		NodeId:      c.NodeID,
		userList:    &UserListBody{},
		nodeRefresh: make(chan struct{}, 1),
		userRefresh: make(chan struct{}, 1),
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

// Debug is disabled because request debug logging can expose authentication credentials and tokens.
// Deprecated: configure application-level sanitized logging instead.
func (c *Client) Debug(enable bool) {
	if enable {
		log.Warn("request debug logging is disabled because it can expose authentication credentials and tokens")
	}
}

// CachedUserList returns a copy of the cached users.
func (c *Client) CachedUserList() []UserInfo {
	c.userMu.Lock()
	var users []UserInfo
	if c.userList != nil {
		users = c.userList.Users
	}
	c.userMu.Unlock()
	return cloneUserInfos(users)
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
	if r.StatusCode() < http.StatusOK || r.StatusCode() >= http.StatusMultipleChoices {
		message := "unexpected HTTP response status"
		if len(r.Body()) > maxAPIErrorMessageBytes {
			message = oversizedAPIErrorMessage
		} else if len(r.Body()) > 0 {
			message = string(r.Body())
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

func (c *Client) checkReportResponse(r *resty.Response, path string, err error) error {
	if err := c.checkResponse(r, path, err); err != nil {
		return err
	}
	if r.StatusCode() == http.StatusNoContent {
		return nil
	}
	var response struct {
		Data *bool `json:"data"`
	}
	if err := json.Unmarshal(r.Body(), &response); err != nil {
		return NewParseError("decode report acknowledgement error", err)
	}
	if response.Data == nil {
		return NewParseError("report response must include a boolean data acknowledgement", nil)
	}
	if !*response.Data {
		return NewBusinessLogicError("report was not acknowledged", path)
	}
	return nil
}

func checkResponseBodySize(path string, body []byte) error {
	if len(body) <= maxResponseBodyBytes {
		return nil
	}
	return NewParseError("response body too large", fmt.Errorf("%s response body is %d bytes, limit is %d", path, len(body), maxResponseBodyBytes))
}

// refreshETag replaces the validator when a full response is accepted.
func refreshETag(current *string, newETag string) {
	*current = newETag
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

func acquireRefresh(ctx context.Context, refresh chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case refresh <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) newRequest(ctx context.Context) *resty.Request {
	return c.client.R().
		SetContext(normalizeContext(ctx)).
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
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		if !shouldRetryGet(r, err) {
			break
		}
		if attempt < getRetryCount {
			timer := time.NewTimer(getRetryDelay(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return r, ctx.Err()
			case <-timer.C:
			}
		}
	}
	if err == nil && r == nil {
		err = errors.New("nil response")
	}
	return r, err
}

func shouldRetryGet(response *resty.Response, err error) bool {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, resty.ErrResponseBodyTooLarge) {
			return false
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return true
		}
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			return dnsError.IsTimeout || dnsError.IsTemporary
		}
		var operationError *net.OpError
		if errors.As(err, &operationError) {
			return true
		}
		var networkError net.Error
		return errors.As(err, &networkError) && networkError.Timeout()
	}
	if response == nil {
		return false
	}
	switch response.StatusCode() {
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func getRetryDelay(attempt int) time.Duration {
	delay := getRetryBackoff << attempt
	return delay + time.Duration(rand.Int64N(int64(delay)))
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	ctx = normalizeContext(ctx)
	if err := acquireRefresh(ctx, c.nodeRefresh); err != nil {
		return nil, newRequestError(apiConfigPath, err)
	}
	defer func() { <-c.nodeRefresh }()

	c.nodeMu.Lock()
	nodeEtag := c.nodeEtag
	c.nodeMu.Unlock()

	r, err := c.getWithRetry(ctx, apiConfigPath, func(req *resty.Request) {
		req.SetHeader(headerIfNoneMatch, nodeEtag)
	})

	if err != nil {
		return nil, newRequestError(apiConfigPath, err)
	}

	if r.StatusCode() == http.StatusNotModified {
		c.nodeMu.Lock()
		defer c.nodeMu.Unlock()
		if c.responseBodyHash == "" || nodeEtag == "" {
			return nil, NewParseError("received 304 without a validated node cache", nil)
		}
		if etag := r.Header().Get(headerETag); etag != "" {
			c.nodeEtag = etag
		}
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
	ctx = normalizeContext(ctx)
	if err := acquireRefresh(ctx, c.userRefresh); err != nil {
		return nil, newRequestError(apiUserPath, err)
	}
	defer func() { <-c.userRefresh }()

	c.userMu.Lock()
	userEtag := c.userEtag
	c.userMu.Unlock()

	r, err := c.getWithRetry(ctx, apiUserPath, func(req *resty.Request) {
		req.SetHeader(headerIfNoneMatch, userEtag)
	})

	if err != nil {
		return nil, newRequestError(apiUserPath, err)
	}

	if r.StatusCode() == http.StatusNotModified {
		c.userMu.Lock()
		defer c.userMu.Unlock()
		if c.userBodyHash == "" || userEtag == "" {
			return nil, NewParseError("received 304 without a validated user cache", nil)
		}
		if etag := r.Header().Get(headerETag); etag != "" {
			c.userEtag = etag
		}
		return cloneUserInfos(c.userList.Users), nil
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
		var cachedUsers []UserInfo
		if c.userList != nil {
			cachedUsers = c.userList.Users
		}
		c.userMu.Unlock()
		return cloneUserInfos(cachedUsers), nil
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

	return c.checkReportResponse(r, apiPushPath, err)
}

func buildOnlinePayload(data map[int][]netip.Addr, nodeID int) map[int][]string {
	out := make(map[int][]string, len(data))
	for uid, ips := range data {
		list := make([]string, 0, len(ips))
		seen := make(map[netip.Addr]struct{}, len(ips))
		for _, ip := range ips {
			ip = ip.Unmap()
			if _, exists := seen[ip]; exists {
				continue
			}
			seen[ip] = struct{}{}
			list = append(list, fmt.Sprintf("%s_%d", ip.String(), nodeID))
		}
		out[uid] = list
	}
	return out
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data map[int][]netip.Addr) error {
	if len(data) == 0 {
		// Skip request when no online users. Newer v2board panels accept empty
		// alive reports, but skipping preserves compatibility with older panels
		// whose cache drivers may fail on empty payloads.
		return nil
	}
	if err := validateOnlineUsers(data); err != nil {
		return err
	}
	r, err := c.newRequest(ctx).
		SetBody(buildOnlinePayload(data, c.config.nodeID)).
		Post(apiAlivePath)

	return c.checkReportResponse(r, apiAlivePath, err)
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
		Alive map[int]*int `json:"alive"`
	}
	if err := json.Unmarshal(r.Body(), &resp); err != nil {
		return nil, NewParseError("decode alive list error", err)
	}

	if resp.Alive == nil {
		return nil, NewParseError("alive response must include a non-null alive object", nil)
	}
	alive := make(map[int]int, len(resp.Alive))
	for uid, count := range resp.Alive {
		if uid <= 0 {
			return nil, NewParseError("decode alive list error", fmt.Errorf("alive uid must be positive: %d", uid))
		}
		if count == nil || *count < 0 {
			return nil, NewParseError("decode alive list error", fmt.Errorf("alive count must be a non-negative integer for uid %d", uid))
		}
		alive[uid] = *count
	}

	return alive, nil
}
