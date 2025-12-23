package pkg

import (
	"fmt"
	"net/http"
)

// ErrorType defines the type of error
type ErrorType string

const (
	// HTTP Errors
	ErrorTypeServerError ErrorType = "ServerError" // 5xx Server Error

	// Special Error Types
	ErrorTypeNetworkError ErrorType = "NetworkError" // Network Connection Error
	ErrorTypeParseError   ErrorType = "ParseError"   // Response Parse Error
	ErrorTypeNotModified  ErrorType = "NotModified"  // 304 Not Modified
	ErrorTypeUnknown      ErrorType = "Unknown"      // Unknown Error
)

// APIError custom API error type
type APIError struct {
	StatusCode int       // HTTP Status Code
	Type       ErrorType // Error Type
	Message    string    // Error Message
	URL        string    // Request URL
	Err        error     // Original Error
}

// Error implements error interface
func (e *APIError) Error() string {
	if e.URL != "" {
		return fmt.Sprintf("[%d] %s: %s (URL: %s)", e.StatusCode, e.Type, e.Message, e.URL)
	}
	return fmt.Sprintf("[%d] %s: %s", e.StatusCode, e.Type, e.Message)
}

// Unwrap implements errors.Unwrap interface
func (e *APIError) Unwrap() error {
	return e.Err
}

// IsServerError checks if it is a server error (4xx/5xx)
func (e *APIError) IsServerError() bool {
	return e.StatusCode >= 400 && e.StatusCode < 600
}

// IsNetworkError checks if it is a network error
func (e *APIError) IsNetworkError() bool {
	return e.Type == ErrorTypeNetworkError
}

// IsParseError checks if it is a parse error
func (e *APIError) IsParseError() bool {
	return e.Type == ErrorTypeParseError
}

// IsNotModified checks if it is 304 Not Modified
func (e *APIError) IsNotModified() bool {
	return e.StatusCode == http.StatusNotModified || e.Type == ErrorTypeNotModified
}

// NewAPIError creates a new API error
func NewAPIError(statusCode int, errorType ErrorType, message string, url string, err error) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Type:       errorType,
		Message:    message,
		URL:        url,
		Err:        err,
	}
}

// NewAPIErrorFromStatusCode infers error type from status code automatically
func NewAPIErrorFromStatusCode(statusCode int, message string, url string, err error) *APIError {
	errorType := getErrorTypeFromStatusCode(statusCode)
	return NewAPIError(statusCode, errorType, message, url, err)
}

// getErrorTypeFromStatusCode gets corresponding error type based on HTTP status code
func getErrorTypeFromStatusCode(statusCode int) ErrorType {
	if statusCode == http.StatusNotModified {
		return ErrorTypeNotModified
	}
	if statusCode >= 400 && statusCode < 600 {
		return ErrorTypeServerError
	}
	return ErrorTypeUnknown
}

// Predefined Common Errors

// NewNetworkError creates a network error
func NewNetworkError(message string, url string, err error) *APIError {
	return NewAPIError(0, ErrorTypeNetworkError, message, url, err)
}

// NewParseError creates a parse error
func NewParseError(message string, err error) *APIError {
	return NewAPIError(0, ErrorTypeParseError, message, "", err)
}

// NewNotModifiedError creates a 304 Not Modified error
func NewNotModifiedError() *APIError {
	return NewAPIError(http.StatusNotModified, ErrorTypeNotModified, "content not modified", "", nil)
}

// NewBusinessLogicError creates a business logic error
// Business logic errors usually come from the Message field in API response, default treated as Server Error (500)
func NewBusinessLogicError(message string, url string) *APIError {
	return NewAPIError(http.StatusInternalServerError, ErrorTypeServerError, message, url, nil)
}
