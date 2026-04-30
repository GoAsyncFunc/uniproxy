# Error Handling Guide

## Overview

This project uses a custom `APIError` type to handle various errors during API calls. `APIError` provides clear error classification for quick troubleshooting.

## Error Types

### HTTP Errors

- `ErrorTypeServerError` (4xx/5xx) - HTTP error responses. Both HTTP 4xx and 5xx responses use this classification; retry only transient 5xx responses unless your application has domain-specific guidance.

### Special Error Types

- `ErrorTypeNetworkError` - Network connection errors (Unable to connect to the server).
- `ErrorTypeParseError` - Response parsing errors (Server returned data that cannot be parsed).
- `ErrorTypeNotModified` (304) - Content not modified (available through `NewNotModifiedError`; high-level client methods handle 304 without returning an error).
- `ErrorTypeUnknown` - Unknown errors.

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "errors"
    "fmt"
    
    "github.com/GoAsyncFunc/uniproxy/pkg"
)

func main() {
    config := &pkg.Config{
        APIHost: "https://api.example.com",
        Key:      "your-token",
        NodeID:   1,
        NodeType: "vless",
    }
    
    client, err := pkg.NewWithError(config)
    if err != nil {
        handleError(err)
        return
    }
    
    // Call API
    users, err := client.GetUserList(context.Background())
    if err != nil {
        handleError(err)
        return
    }
    
    fmt.Printf("Fetched %d users\n", len(users))
}

func handleError(err error) {
    // Check if it is APIError
    var apiErr *pkg.APIError
    if errors.As(err, &apiErr) {
        // Determine error type without logging raw APIError fields.
        if apiErr.IsServerError() {
            fmt.Printf("HTTP Error [%d]\n", apiErr.StatusCode)
            fmt.Println("HTTP request failed; inspect status code before retrying")
        } else if apiErr.IsNetworkError() {
            fmt.Println("Network Error")
            fmt.Println("Please check your network connection")
        } else if apiErr.IsParseError() {
            fmt.Println("Parse Error")
            fmt.Println("Server returned invalid data")
        }
        
        // Error() formats redacted URL and lower-level error text.
        fmt.Printf("Details: %s\n", apiErr.Error())
    } else {
        // Non-APIError type
        fmt.Printf("Unknown Error: %v\n", err)
    }
}
```

### Quick Error Type Check

#### Check for Server Errors

```go
var apiErr *pkg.APIError
if errors.As(err, &apiErr) {
    if apiErr.IsServerError() {
        // 4xx/5xx HTTP responses share this classification.
        // Retry only transient 5xx responses unless your application knows otherwise.
        fmt.Println("HTTP request failed")
    }
}
```

#### Check for Special Error Types

```go
if apiErr.IsNetworkError() {
    // Network connection error
    fmt.Println("Unable to connect to server, check network")
}

if apiErr.IsParseError() {
    // Response parsing error
    fmt.Println("Server returned invalid data, client update might be needed")
}

// High-level client methods handle 304 responses directly:
// GetNodeInfo returns (nil, nil), and GetUserList returns cached users.
// NewNotModifiedError remains available for lower-level/custom integrations.
if apiErr.IsNotModified() {
    fmt.Println("Not modified in a custom integration")
}
```

#### Check Specific Status Codes

```go
switch apiErr.StatusCode {
case 401:
    fmt.Println("Authentication failed, check Key")
case 403:
    fmt.Println("Permission denied")
case 404:
    fmt.Println("Resource not found")
case 500:
    fmt.Println("Internal Server Error")
case 503:
    fmt.Println("Service Temporarily Unavailable")
}
```

### Retry Strategy Example

Decide whether to retry based on error type. Built-in automatic retries are only applied to GET requests; reporting POST requests are not automatically retried by the client.

```go
import "time"

func callAPIWithRetry(client *pkg.Client) error {
    maxRetries := 3
    
    for i := 0; i < maxRetries; i++ {
        users, err := client.GetUserList(context.Background())
        if err == nil {
            // Success
            return nil
        }
        
        var apiErr *pkg.APIError
        if errors.As(err, &apiErr) {
            // Network errors and HTTP 5xx responses may be retried for GET requests.
            // HTTP 4xx responses usually require caller/configuration changes.
            if apiErr.IsNetworkError() || apiErr.StatusCode >= 500 {
                fmt.Printf("Request failed, retrying %d/%d: %s\n", i+1, maxRetries, err)
                time.Sleep(time.Second * time.Duration(i+1))
                continue
            }
        }
        
        // Other unknown errors, do not retry
        return err
    }
    
    return fmt.Errorf("reached max retries")
}
```

### Error Wrapping Support

`APIError` implements the `errors.Unwrap()` interface with sanitized lower-level error text. Arbitrary underlying error identity is not preserved, because network errors can include raw URLs. Safe sentinel matching is preserved for known cases:

```go
var apiErr *pkg.APIError
if errors.As(err, &apiErr) {
    if errors.Is(apiErr, context.DeadlineExceeded) {
        fmt.Println("Request timed out")
    }
}
```

### Logging Example

```go
func logError(err error) {
    var apiErr *pkg.APIError
    if errors.As(err, &apiErr) {
        fields := map[string]interface{}{
            "status_code": apiErr.StatusCode,
            "error_type":  apiErr.Type,
            "error":       apiErr.Error(),
        }
        
        if apiErr.IsServerError() {
            log.WithFields(fields).Error("Server Error")
        } else if apiErr.IsNetworkError() {
            log.WithFields(fields).Error("Network Error")
        } else {
            log.WithFields(fields).Error("Other Error")
        }
        
        // Avoid logging apiErr.Err directly because lower-level network errors can include raw URLs.
    } else {
        log.WithError(err).Error("Unknown Error")
    }
}
```

## Error Message Format

The `Error()` method of `APIError` returns formatted error messages:

- With URL: `[404] ServerError: resource not found (URL: https://api.example.com/users)`
- Without URL: `[500] ServerError: database connection failed`
- Network Error: `[0] NetworkError: connection timeout (URL: https://api.example.com)`

Sensitive query parameters such as `token`, `key`, `auth`, and `authorization` are redacted when `APIError.Error()` formats URLs. API error response bodies are also sanitized for common query, JSON, and bearer-token formats before being surfaced to callers.

## High-Level 304 Behavior

The high-level client methods do not surface 304 responses as ordinary errors:

- `GetNodeInfo` returns `(nil, nil)` when the panel responds with `304 Not Modified`.
- `GetUserList` returns the cached user list when the panel responds with `304 Not Modified`.
- `NewNotModifiedError` is still available for lower-level or custom integrations that need to represent 304 as an `APIError`.

## Creating Custom Errors

### Method 1: Infer Error Type from Status Code (Recommended)

```go
// All HTTP 4xx/5xx errors are classified as HTTP errors
err := pkg.NewAPIErrorFromStatusCode(404, "user not found", "https://api.example.com/users/123", nil)
// Result: Type = ErrorTypeServerError

err := pkg.NewAPIErrorFromStatusCode(500, "database error", "https://api.example.com/data", nil)
// Result: Type = ErrorTypeServerError
```

### Method 2: Use Predefined Factory Functions

```go
// Create network error
err := pkg.NewNetworkError("connection timeout", "https://api.example.com", originalErr)

// Create parse error
err := pkg.NewParseError("invalid JSON response", originalErr)

// Create 304 Not Modified error
err := pkg.NewNotModifiedError()
```

### Method 3: Fully Custom

```go
err := pkg.NewAPIError(
    418,                        // Status Code
    pkg.ErrorTypeServerError,   // Error Type
    "I'm a teapot",            // Message
    "https://api.example.com",  // URL
    nil,                       // Original Error
)
```

## Best Practices

1. **Distinguish error types for handling strategies**:
   - **HTTP Error (4xx/5xx)**: All HTTP error responses use `ErrorTypeServerError`; retry only transient 5xx responses.
   - **Network Error**: Network issues may be retried for idempotent calls.
   - **Parse Error**: Data format issues, log and check API version.

2. **Use `errors.As()` to safely cast errors**:
   ```go
   var apiErr *pkg.APIError
   if errors.As(err, &apiErr) {
       // Safely access APIError fields and methods
   }
   ```

3. **Log safely**: Prefer `APIError.Error()` for logs. Do not log raw `APIError.URL`, `APIError.Message`, or `APIError.Err` fields without explicit redaction.

4. **Handle 304 Not Modified**: high-level client methods handle this without returning an error; use `IsNotModified` only for custom lower-level integrations.

5. **Preserve error context safely**: constructors store a redacted error summary and preserve only safe sentinel matching for common cases such as context cancellation and response-body limits. Log `APIError.Error()` instead of lower-level error internals.

6. **Handle validation errors normally**: caller-input validation errors, such as invalid report payloads, may be plain errors rather than `APIError` values.

## API Error Field Description

```go
type APIError struct {
    StatusCode int       // HTTP Status Code (0 for non-HTTP errors, e.g., network error)
    Type       ErrorType // Error classification (ServerError, NetworkError, ParseError, NotModified, Unknown)
    Message    string    // Human-readable error message
    URL        string    // Request URL where error occurred
    Err        error     // Redacted lower-level error summary (optional)
}
```

## Error Type Decision Tree

```
Can connect to server?
├─ No → ErrorTypeNetworkError
└─ Yes
    └─ Can parse response?
        ├─ No → ErrorTypeParseError
        └─ Yes
            └─ HTTP Status Code
                ├─ 304 → ErrorTypeNotModified
                ├─ 4xx/5xx → ErrorTypeServerError
                └─ Others → ErrorTypeUnknown
```
