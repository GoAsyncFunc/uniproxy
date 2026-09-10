package pkg

import (
	"context"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClientTLSCertificateValidation(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		name := "untrusted"
		if trusted {
			name = "trusted"
		}
		t.Run(name, func(t *testing.T) {
			var attempts, requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write([]byte(`{"users":[]}`)) }))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					attempts.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			client, err := NewWithError(&Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: Vless, Timeout: 5})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			if trusted {
				// Test-only trust injection; certificate verification stays enabled.
				client.client.SetRootCertificateFromString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
			}
			_, err = client.GetUserList(context.Background())
			if trusted {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("untrusted certificate accepted")
			}
			if attempts.Load() != 1 {
				t.Fatalf("TLS connection attempts=%d want=1 (no certificate-error retry)", attempts.Load())
			}
			want := int32(0)
			if trusted {
				want = 1
			}
			if requests.Load() != want {
				t.Fatalf("HTTP requests=%d want=%d", requests.Load(), want)
			}
		})
	}
}
