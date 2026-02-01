package pkg

import (
	"encoding/json"
	"fmt"
)

// -- VMess --
type VMessHandler struct{}

func (h *VMessHandler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node VMessNode
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode vmess params error: %w", err)
	}

	info.VMess = &node
	info.Security = node.Tls

	return node.GetCommonNode(), nil
}

// -- VLESS --
type VlessHandler struct{}

func (h *VlessHandler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node VlessNode
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode vless params error: %w", err)
	}

	info.Vless = &node
	info.Security = node.Tls

	return node.GetCommonNode(), nil
}

// -- Shadowsocks --
type ShadowsocksHandler struct{}

func (h *ShadowsocksHandler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node ShadowsocksNode
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode shadowsocks params error: %w", err)
	}

	info.Shadowsocks = &node
	info.Security = None

	return node.GetCommonNode(), nil
}

// -- Trojan --
type TrojanHandler struct{}

func (h *TrojanHandler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node TrojanNode
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode trojan params error: %w", err)
	}

	info.Trojan = &node
	info.Security = Tls

	return node.GetCommonNode(), nil
}

// -- Tuic --
type TuicHandler struct{}

func (h *TuicHandler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node TuicNode
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode tuic params error: %w", err)
	}

	info.Tuic = &node
	info.Security = Tls

	return node.GetCommonNode(), nil
}

// -- Hysteria --
type HysteriaHandler struct{}

func (h *HysteriaHandler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node HysteriaNode
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode hysteria params error: %w", err)
	}

	info.Hysteria = &node
	info.Security = Tls

	return node.GetCommonNode(), nil
}

// -- Hysteria2 --
type Hysteria2Handler struct{}

func (h *Hysteria2Handler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node Hysteria2Node
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode hysteria2 params error: %w", err)
	}

	info.Hysteria2 = &node
	info.Security = Tls

	return node.GetCommonNode(), nil
}

// -- AnyTls --
type AnyTlsHandler struct{}

func (h *AnyTlsHandler) ParseConfig(info *NodeInfo, data []byte) (*CommonNode, error) {
	var node AnyTlsNode
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("decode anytls params error: %w", err)
	}

	info.AnyTls = &node
	info.Security = Tls

	return node.GetCommonNode(), nil
}
