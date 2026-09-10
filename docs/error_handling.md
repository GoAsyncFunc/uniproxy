# Error Handling Guide

`uniproxy` returns a custom `*APIError` from API methods to make
classification, redaction, and retry decisions explicit. This guide covers the
types, the constructors, and the patterns callers should follow.

## Error types

```go
const (
    ErrorTypeServerError  ErrorType = "ServerError"  // HTTP 4xx/5xx response
    ErrorTypeNetworkError ErrorType = "NetworkError" // network / connection failure
    ErrorTypeParseError   ErrorType = "ParseError"   // response could not be decoded/validated
    ErrorTypeNotModified  ErrorType = "NotModified"  // HTTP 304 (low-level only)
    ErrorTypeUnknown      ErrorType = "Unknown"      // fallback
)
```

`ErrorTypeServerError` covers **both 4xx and 5xx** responses. Use the status
code to decide whether a retry is appropriate — only transient 5xx responses
should generally be retried.

The high-level methods `GetNodeInfo` and `GetUserList` handle valid 304 responses
internally (returning `(nil, nil)` and the cached user list respectively).
A 304 without a previously validated response and a non-empty request ETag is
an `ErrorTypeParseError`, not a successful empty result.
`NewNotModifiedError` is exposed for callers building custom integrations.

## APIError shape

```go
type APIError struct {
    StatusCode int       // HTTP status, or 0 for non-HTTP errors
    Type       ErrorType // Classification (Server/Network/Parse/NotModified/Unknown)
    Message    string    // Human-readable, sanitized
    URL        string    // Request URL with sensitive query params redacted
    Err        error     // Sanitized lower-level error (optional)
}
```

`Error()` formats as:

- With URL: `[404] ServerError: resource not found (URL: https://api.example.com/users)`
- Without URL: `[500] ServerError: database connection failed`
- Network: `[0] NetworkError: connection timeout (URL: https://api.example.com)`

Sensitive query keys (`token`, `key`, `auth`, `authorization`, `access_token`,
`api_key`, `apikey`, `x-api-key`, `client_secret`, `refresh_token`,
`id_token`, `mldsa65seed`, `secret`, `password`, `signature`, `sig`) are
redacted in URLs. Bearer tokens and the same key set are also redacted from
embedded JSON/query/colon-separated text in messages and wrapped errors.
Inputs longer than 8 KiB are replaced with a fixed summary before redaction
to bound processing and allocation costs. Redaction can expand short input;
the resulting text is also capped at 8 KiB plus a truncation marker.

## Basic usage

```go
package main

import (
    "context"
    "errors"
    "fmt"

    "github.com/GoAsyncFunc/uniproxy/pkg"
)

func main() {
    client, err := pkg.NewWithError(&pkg.Config{
        APIHost:  "https://api.example.com",
        Key:      "your-token",
        NodeID:   1,
        NodeType: "vless",
    })
    if err != nil {
        handleError(err)
        return
    }

    users, err := client.GetUserList(context.Background())
    if err != nil {
        handleError(err)
        return
    }
    fmt.Printf("Fetched %d users\n", len(users))
}

func handleError(err error) {
    var apiErr *pkg.APIError
    if !errors.As(err, &apiErr) {
        fmt.Printf("Unknown Error: %v\n", err)
        return
    }

    switch {
    case apiErr.IsServerError():
        fmt.Printf("HTTP %d — inspect status before retrying\n", apiErr.StatusCode)
    case apiErr.IsNetworkError():
        fmt.Println("Network error — check connectivity")
    case apiErr.IsParseError():
        fmt.Println("Parse error — server returned invalid data")
    }

    // Error() returns redacted text; safe to log directly.
    fmt.Printf("Details: %s\n", apiErr.Error())
}
```

## Classifying errors

```go
var apiErr *pkg.APIError
if errors.As(err, &apiErr) {
    apiErr.IsServerError()  // any HTTP 4xx or 5xx
    apiErr.IsNetworkError() // Type == NetworkError
    apiErr.IsParseError()   // Type == ParseError
    apiErr.IsNotModified()  // StatusCode == 304 || Type == NotModified
}
```

Match specific status codes when behavior differs:

```go
switch apiErr.StatusCode {
case 401:
    // re-authenticate; check Key
case 403:
    // permission denied
case 404:
    // resource missing
case 500, 502, 503, 504:
    // transient, eligible for retry
}
```

## Retry strategy

`uniproxy` retries GET requests at most twice for HTTP 500/502/503/504,
connection failures, temporary DNS errors, timeouts, and interrupted reads.
The first retry waits 100–200ms and the second waits 200–400ms, with random
jitter. Oversized responses, canceled contexts, permanent DNS errors,
certificate validation failures, and other HTTP statuses are not retried.
Caller cancellation also interrupts backoff and node/user refresh-lock waits.
`Config.Timeout` applies to each HTTP attempt, not the entire retry sequence.

The referenced v2board implementation uses HTTP 500 for invalid tokens and
missing nodes too. These responses are eligible for the bounded GET retry
policy, but operators must fix the configuration if the error persists.

POST reports (`ReportUserTraffic`, `ReportNodeOnlineUsers`) are **not** retried.
They require a 2xx response with `{"data":true}`, or HTTP 204 for compatibility.
Malformed or missing acknowledgements return parse errors; `{"data":false}`
returns a business-logic error. Redirects are rejected before following them,
and their original HTTP status is preserved in `APIError.StatusCode`.

Do not infer that an errored traffic report was never processed. The panel
dispatches accounting jobs before acknowledging the request; a lost response
or partial server failure can leave the result ambiguous. Retrying the same
traffic without reconciliation or server-side idempotency can double-count
it. An application must choose its own recovery policy rather than blindly
replaying every network or 5xx failure.

## Sentinel matching with `errors.Is`

`APIError.Unwrap()` returns a *sanitized* wrapper rather than the original
underlying error — raw lower-level errors can contain URLs or credentials.
Identity is therefore not preserved, but the wrapper still answers
`errors.Is` for the common cases:

- `context.Canceled`
- `context.DeadlineExceeded`
- `resty.ErrResponseBodyTooLarge`

```go
var apiErr *pkg.APIError
if errors.As(err, &apiErr) && errors.Is(apiErr, context.DeadlineExceeded) {
    // request timed out
}
```

## Safe logging

```go
func logError(err error) {
    var apiErr *pkg.APIError
    if !errors.As(err, &apiErr) {
        log.WithError(err).Error("non-api error")
        return
    }
    // Error() is the only field guaranteed redacted.
    log.WithFields(map[string]any{
        "status_code": apiErr.StatusCode,
        "error_type":  apiErr.Type,
        "error":       apiErr.Error(),
    }).Error("api error")
}
```

Do **not** log `apiErr.URL`, `apiErr.Message`, or `apiErr.Err` directly
without further redaction — they may contain content that escaped sanitation.

## Constructors

```go
// Infer type from status code (recommended for HTTP errors).
pkg.NewAPIErrorFromStatusCode(404, "user not found", "https://api.example.com/users/123", nil)

// Specialized helpers.
pkg.NewNetworkError("connection timeout", "https://api.example.com", originalErr)
pkg.NewParseError("invalid JSON response", originalErr)
pkg.NewNotModifiedError()
pkg.NewBusinessLogicError("rate limit exceeded", "https://api.example.com")

// Fully custom.
pkg.NewAPIError(418, pkg.ErrorTypeServerError, "I'm a teapot", "https://api.example.com", nil)
```

All constructors sanitize `message`, `url`, and `err` before storing.

## Validation vs API errors

Caller-input validation errors (e.g. non-positive UIDs, invalid `netip.Addr`,
duplicate users) may be returned as plain `error` values, not `*APIError`.
Use `errors.As` to branch:

```go
var apiErr *pkg.APIError
if errors.As(err, &apiErr) {
    // request-level failure
} else {
    // local validation failure
}
```

## Decision tree

```
network reachable?
├─ no  → ErrorTypeNetworkError
└─ yes
   └─ response parses?
      ├─ no  → ErrorTypeParseError
      └─ yes
         └─ status code
            ├─ 304     → ErrorTypeNotModified  (low-level only)
            ├─ 4xx/5xx → ErrorTypeServerError
            └─ other   → ErrorTypeUnknown
```

## Best practices

1. **Use `errors.As`** to extract `*APIError`; never type-assert.
2. **Log `apiErr.Error()`**, not raw fields.
3. **Retry only transient errors** — network failures and 5xx status codes.
   4xx errors usually require configuration or input changes.
4. **Don't rely on 304 surfacing as an error** from high-level methods;
   `GetNodeInfo` and `GetUserList` already handle it.
5. **Treat sentinel matching as best-effort** — only the documented sentinels
   (`context.Canceled`, `context.DeadlineExceeded`,
   `resty.ErrResponseBodyTooLarge`) are guaranteed to match.
