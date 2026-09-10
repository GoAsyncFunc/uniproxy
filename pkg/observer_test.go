package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	resty "github.com/go-resty/resty/v2"
)

func TestObserverRetriesAndParseSemantics(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"error":"not a user list"}`))
	}))
	defer server.Close()
	var events []RequestEvent
	client, err := NewWithError(&Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: Vless, Observer: func(e RequestEvent) { events = append(events, e) }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	_, err = client.GetUserList(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsParseError() {
		t.Fatalf("expected parse error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d", len(events))
	}
	for i, e := range events {
		want := RequestHTTPError
		if i == 2 {
			want = RequestSucceeded
		}
		if e.Attempt != i+1 || e.Method != http.MethodGet || e.Path != apiUserPath || e.Outcome != want || e.Duration < 0 {
			t.Fatalf("unexpected event: %+v", e)
		}
	}
}

func TestObserverClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		err    error
		want   RequestOutcome
	}{
		{"success", 204, nil, RequestSucceeded}, {"304", 304, nil, RequestNotModified}, {"redirect", 302, nil, RequestHTTPError},
		{"network", 0, errors.New("token=fixture-secret"), RequestNetworkError}, {"nil response", 0, nil, RequestNetworkError},
		{"canceled", 0, context.Canceled, RequestCanceled}, {"deadline", 0, context.DeadlineExceeded, RequestDeadlineExceeded},
		{"too large", 200, resty.ErrResponseBodyTooLarge, RequestResponseTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var event RequestEvent
			client := &Client{observer: func(e RequestEvent) { event = e }}
			var response *resty.Response
			if tc.status != 0 {
				response = &resty.Response{RawResponse: &http.Response{StatusCode: tc.status}}
			}
			client.observeRequest(http.MethodGet, apiUserPath, 1, time.Now(), response, tc.err)
			if event.Outcome != tc.want || event.StatusCode != tc.status {
				t.Fatalf("unexpected event: %+v", event)
			}
		})
	}
}

func TestObserverPanicAndConstructionSnapshot(t *testing.T) {
	calls, observed := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte(`{"data":true}`)) }))
	defer server.Close()
	config := &Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: Vless, Observer: func(e RequestEvent) {
		observed++
		if e.Method != http.MethodPost || e.Path != apiPushPath || e.Attempt != 1 {
			t.Error("unexpected report event")
		}
		panic("fixture-secret")
	}}
	client, err := NewWithError(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	config.Observer = func(RequestEvent) { t.Error("mutated config observer used") }
	if err := client.ReportUserTraffic(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 0}}); err == nil {
		t.Fatal("expected validation error")
	}
	if observed != 0 || calls != 0 {
		t.Fatal("no-op/invalid input emitted requests")
	}
	if err := client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 1, Upload: 1}}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || observed != 1 {
		t.Fatal("observer panic caused missing/duplicate report")
	}
}

func TestObserverConcurrentReports(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	var mu sync.Mutex
	var events []RequestEvent
	client, err := NewWithError(&Config{APIHost: server.URL, Key: "fixture-token", NodeID: 1, NodeType: Vless, Observer: func(e RequestEvent) { mu.Lock(); defer mu.Unlock(); events = append(events, e) }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 1, Upload: 1}}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 20 {
		t.Fatalf("events=%d", len(events))
	}
}
