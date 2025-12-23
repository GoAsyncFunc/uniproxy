# Error Handling Guide

## Overview

This project uses a custom `APIError` type to handle various errors during API calls. `APIError` provides clear error classification for quick troubleshooting.

## Error Types

### HTTP Errors

- `ErrorTypeServerError` (4xx/5xx) - Server-side errors (All HTTP 4xx and 5xx errors are classified as server errors).

### Special Error Types

- `ErrorTypeNetworkError` - Network connection errors (Unable to connect to the server).
- `ErrorTypeParseError` - Response parsing errors (Server returned data that cannot be parsed).
- `ErrorTypeNotModified` (304) - Content not modified (Cache is valid).
- `ErrorTypeUnknown` - Unknown errors.

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "errors"
    
    "github.com/GoAsyncFunc/uniproxy/pkg"
)

func main() {
    config := &pkg.Config{
        APIHost: "https://api.example.com",
        Token:   "your-token",
    }
    
    client := pkg.New(config)
    
    // Call API
    users, err := client.Users(1, pkg.VMess)
    if err != nil {
        handleError(err)
        return
    }
    
    fmt.Printf("Fetched %d users\n", len(*users))
}

func handleError(err error) {
    // Check if it is APIError
    var apiErr *pkg.APIError
    if errors.As(err, &apiErr) {
        // Determine error type
        if apiErr.IsServerError() {
            fmt.Printf("Server Error [%d]: %s\n", apiErr.StatusCode, apiErr.Message)
            fmt.Println("Server issue, please retry later or contact admin")
        } else if apiErr.IsNetworkError() {
            fmt.Printf("Network Error: %s\n", apiErr.Message)
            fmt.Println("Please check your network connection")
        } else if apiErr.IsParseError() {
            fmt.Printf("Parse Error: %s\n", apiErr.Message)
            fmt.Println("Server returned invalid data")
        } else if apiErr.IsNotModified() {
            fmt.Println("Data not modified, can use cache")
        }
        
        // Print full error info (including URL)
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
        // 4xx/5xx errors - Server side issues
        // All HTTP errors are classified as server errors
        fmt.Println("Server issue, please retry later")
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

if apiErr.IsNotModified() {
    // 304 Not Modified - Not an error, implies cache usage
    fmt.Println("Data not modified, using cache")
}
```

#### Check Specific Status Codes

```go
switch apiErr.StatusCode {
case 401:
    fmt.Println("Authentication failed, check Token")
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

Decide whether to retry based on error type:

```go
import "time"

func callAPIWithRetry(client *pkg.Client) error {
    maxRetries := 3
    
    for i := 0; i < maxRetries; i++ {
        users, err := client.Users(1, pkg.VMess)
        if err == nil {
            // Success
            return nil
        }
        
        var apiErr *pkg.APIError
        if errors.As(err, &apiErr) {
            // Server errors or network errors can be retried
            if apiErr.IsServerError() || apiErr.IsNetworkError() {
                fmt.Printf("Request failed, retrying %d/%d: %s\n", i+1, maxRetries, err)
                time.Sleep(time.Second * time.Duration(i+1)) // Exponential backoff
                continue
            }
            
            // 304 Not Modified is not an error, no retry needed
            if apiErr.IsNotModified() {
                return nil // Use cache
            }
        }
        
        // Other unknown errors, do not retry
        return err
    }
    
    return fmt.Errorf("reached max retries")
}
```

### Error Wrapping Support

`APIError` implements the `errors.Unwrap()` interface, supporting Go's standard error wrapping:

```go
import "syscall"

// Example: Check for specific underlying error
var apiErr *pkg.APIError
if errors.As(err, &apiErr) {
    // Get original error
    if apiErr.Err != nil {
        fmt.Printf("Original error: %v\n", apiErr.Err)
    }
    
    // Use errors.Is to check for specific error
    if errors.Is(apiErr, syscall.ECONNREFUSED) {
        fmt.Println("Connection refused")
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
            "message":     apiErr.Message,
            "url":         apiErr.URL,
        }
        
        if apiErr.IsServerError() {
            log.WithFields(fields).Error("Server Error")
        } else if apiErr.IsNetworkError() {
            log.WithFields(fields).Error("Network Error")
        } else {
            log.WithFields(fields).Error("Other Error")
        }
        
        // Log original error (if any)
        if apiErr.Err != nil {
            log.WithError(apiErr.Err).Debug("Original Error")
        }
    } else {
        log.WithError(err).Error("Unknown Error")
    }
}
```

## Error Message Format

The `Error()` method of `APIError` returns formatted error messages:

- With URL: `[404] ServerError: resource not found (URL: http://api.example.com/users)`
- Without URL: `[500] ServerError: database connection failed`
- Network Error: `[0] NetworkError: connection timeout (URL: http://api.example.com)`

## Creating Custom Errors

### Method 1: Infer Error Type from Status Code (Recommended)

```go
// All HTTP 4xx/5xx errors are classified as server errors
err := pkg.NewAPIErrorFromStatusCode(404, "user not found", "http://api.example.com/users/123", nil)
// Result: Type = ErrorTypeServerError

err := pkg.NewAPIErrorFromStatusCode(500, "database error", "http://api.example.com/data", nil)
// Result: Type = ErrorTypeServerError
```

### Method 2: Use Predefined Factory Functions

```go
// Create network error
err := pkg.NewNetworkError("connection timeout", "http://api.example.com", originalErr)

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
    "http://api.example.com",  // URL
    nil,                       // Original Error
)
```

## Best Practices

1. **Distinguish error types for handling strategies**:
   - **Server Error (4xx/5xx)**: All HTTP errors are server errors, can be retried.
   - **Network Error**: Network issues, can be retried.
   - **Parse Error**: Data format issues, log and check API version.

2. **Use `errors.As()` to safely cast errors**:
   ```go
   var apiErr *pkg.APIError
   if errors.As(err, &apiErr) {
       // Safely access APIError fields and methods
   }
   ```

3. **Log detailed logs**: Use `APIError` fields to log full error context.

4. **Handle 304 Not Modified**: Not a real error, indicates cache usage.

5. **Preserve error chain**: Pass original error when creating errors for deep debugging.

## API Error Field Description

```go
type APIError struct {
    StatusCode int       // HTTP Status Code (0 for non-HTTP errors, e.g., network error)
    Type       ErrorType // Error Type (ClientError/ServerError etc.)
    Message    string    // Human-readable error message
    URL        string    // Request URL where error occurred
    Err        error     // Original error (Optional, for error wrapping)
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
