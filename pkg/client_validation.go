package pkg

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

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
