package pkg

// NodeHandler defines the interface that all protocol handlers must implement.
type NodeHandler interface {
	// ParseConfig parses the raw JSON body and assigns the result to the matching field in NodeInfo.
	// It returns the CommonNode for shared processing.
	ParseConfig(node *NodeInfo, data []byte) (*CommonNode, error)
}
