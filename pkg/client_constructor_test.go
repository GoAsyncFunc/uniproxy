package pkg

import (
	"net/http"
	"testing"
)

type unexpectedDefaultTransport struct{}

func (unexpectedDefaultTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("must not perform a request")
}

func TestConstructorsRejectUnsupportedDefaultTransport(t *testing.T) {
	// Global transport mutation must not run in parallel with other tests.
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, transport := range []http.RoundTripper{unexpectedDefaultTransport{}, nil, (*http.Transport)(nil)} {
		http.DefaultTransport = transport
		config := &Config{APIHost: "https://example.com", Key: "fixture-token", NodeID: 1, NodeType: Vless}
		client, err := NewWithError(config)
		if err == nil || client != nil {
			t.Fatal("expected construction error, not a client")
		}
		if New(config) != nil {
			t.Fatal("legacy constructor must return nil")
		}
	}
}

func TestTransportClonesSupportedGlobalSettings(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	base := original.(*http.Transport).Clone()
	base.MaxIdleConns = 37
	http.DefaultTransport = base
	config := &Config{APIHost: "https://example.com", Key: "fixture-token", NodeID: 1, NodeType: "v2ray"}
	client, err := NewWithError(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	transport := client.client.GetClient().Transport.(*http.Transport)
	if transport == base || transport.MaxIdleConns != 37 {
		t.Fatal("default transport settings not independently cloned")
	}
	if client.config.nodeType != Vmess {
		t.Fatal("legacy protocol normalization changed")
	}
	transport.MaxIdleConns = 12
	if base.MaxIdleConns != 37 {
		t.Fatal("global transport mutated")
	}
}
