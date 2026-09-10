package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	resty "github.com/go-resty/resty/v2"
)

func TestUserResponseExactBodyLimit(t *testing.T) {
	for _, extra := range []int{0, 1} {
		name := "at_limit"
		if extra != 0 {
			name = "over_limit"
		}
		t.Run(name, func(t *testing.T) {
			const envelope = `{"users":[]}`
			body := envelope + strings.Repeat(" ", maxResponseBodyBytes+extra-len(envelope))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client := newTestClient(t, server.URL, Vless)
			defer client.CloseIdleConnections()
			users, err := client.GetUserList(context.Background())
			if extra == 0 {
				if err != nil || len(users) != 0 {
					t.Fatalf("at limit: %v", err)
				}
			} else if !errors.Is(err, resty.ErrResponseBodyTooLarge) {
				t.Fatalf("over limit: %v", err)
			}
		})
	}
}
