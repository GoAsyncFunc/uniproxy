package pkg

import (
	"context"
	"errors"
	"net/http"
	"time"

	resty "github.com/go-resty/resty/v2"
)

// RequestOutcome describes transport/status results, not parsed API success.
type RequestOutcome string

const (
	RequestSucceeded        RequestOutcome = "http_success"
	RequestNotModified      RequestOutcome = "not_modified"
	RequestHTTPError        RequestOutcome = "http_error"
	RequestNetworkError     RequestOutcome = "network_error"
	RequestCanceled         RequestOutcome = "canceled"
	RequestDeadlineExceeded RequestOutcome = "deadline_exceeded"
	RequestResponseTooLarge RequestOutcome = "response_too_large"
)

// RequestEvent contains bounded-cardinality metadata only. Path is a library
// endpoint constant, never a URL or caller-provided value. Attempt starts at 1.
// Duration covers one HTTP attempt, excluding backoff, refresh wait, parsing,
// and the observer itself. HTTP success is not an acknowledgement of job completion.
type RequestEvent struct {
	Method     string
	Path       string
	Attempt    int
	Duration   time.Duration
	StatusCode int // 0 when no HTTP response is available.
	Outcome    RequestOutcome
}

// RequestObserver is invoked synchronously after each HTTP attempt, before
// parsing or retry decisions. It must return promptly, support concurrent calls,
// and must not call back into the same Client (refresh operations may be locked).
// Panics are isolated and discarded, without logging their potentially secret
// values. Slow/blocking observers still delay their callers, including retries.
type RequestObserver func(RequestEvent)

func (c *Client) observeRequest(method, path string, attempt int, started time.Time, response *resty.Response, err error) {
	if c.observer == nil {
		return
	}
	event := RequestEvent{Method: method, Path: path, Attempt: attempt, Duration: time.Since(started)}
	if response != nil && response.RawResponse != nil {
		event.StatusCode = response.StatusCode()
	}
	switch {
	case errors.Is(err, context.Canceled):
		event.Outcome = RequestCanceled
	case errors.Is(err, resty.ErrResponseBodyTooLarge):
		event.Outcome = RequestResponseTooLarge
	case errors.Is(err, context.DeadlineExceeded):
		event.Outcome = RequestDeadlineExceeded
	case err != nil || response == nil:
		event.Outcome = RequestNetworkError
	case event.StatusCode == http.StatusNotModified:
		event.Outcome = RequestNotModified
	case event.StatusCode >= 200 && event.StatusCode < 300:
		event.Outcome = RequestSucceeded
	default:
		event.Outcome = RequestHTTPError
	}
	// Observability must not turn a completed report into a caller-visible panic
	// that could cause it to be resent. Do not recover transport/parser panics.
	defer func() { _ = recover() }()
	c.observer(event)
}

func (c *Client) postReport(ctx context.Context, path string, body any) error {
	started := time.Now()
	response, err := c.newRequest(ctx).SetBody(body).Post(path)
	c.observeRequest(http.MethodPost, path, 1, started, response, err)
	return c.checkReportResponse(response, path, err)
}
