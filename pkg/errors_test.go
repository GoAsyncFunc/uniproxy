package pkg

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		apiError *APIError
		want     string
	}{
		{
			name: "Server Error - 401",
			apiError: &APIError{
				StatusCode: 401,
				Type:       ErrorTypeServerError,
				Message:    "invalid token",
				URL:        "http://example.com/api/users",
			},
			want: "[401] ServerError: invalid token (URL: http://example.com/api/users)",
		},
		{
			name: "Server Error - 500 Internal Server",
			apiError: &APIError{
				StatusCode: 500,
				Type:       ErrorTypeServerError,
				Message:    "database connection failed",
				URL:        "http://example.com/api/config",
			},
			want: "[500] ServerError: database connection failed (URL: http://example.com/api/config)",
		},
		{
			name: "Error without URL",
			apiError: &APIError{
				StatusCode: 404,
				Type:       ErrorTypeServerError,
				Message:    "resource not found",
				URL:        "",
			},
			want: "[404] ServerError: resource not found",
		},
		{
			name: "Network Error",
			apiError: &APIError{
				StatusCode: 0,
				Type:       ErrorTypeNetworkError,
				Message:    "connection timeout",
				URL:        "http://example.com",
			},
			want: "[0] NetworkError: connection timeout (URL: http://example.com)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.apiError.Error(); got != tt.want {
				t.Errorf("APIError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIError_IsServerError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"500 Internal Server", 500, true},
		{"501 Not Implemented", 501, true},
		{"503 Service Unavailable", 503, true},
		{"599 Custom Server Error", 599, true},
		{"400 Bad Request", 400, true},
		{"404 Not Found", 404, true},
		{"200 OK", 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAPIErrorFromStatusCode(tt.statusCode, "test error", "", nil)
			if got := err.IsServerError(); got != tt.want {
				t.Errorf("APIError.IsServerError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetErrorTypeFromStatusCode(t *testing.T) {
	tests := []struct {
		statusCode int
		want       ErrorType
	}{
		{400, ErrorTypeServerError},
		{401, ErrorTypeServerError},
		{403, ErrorTypeServerError},
		{404, ErrorTypeServerError},
		{499, ErrorTypeServerError},
		{500, ErrorTypeServerError},
		{501, ErrorTypeServerError},
		{503, ErrorTypeServerError},
		{599, ErrorTypeServerError},
		{304, ErrorTypeNotModified},
		{200, ErrorTypeUnknown},
		{300, ErrorTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("StatusCode_%d", tt.statusCode), func(t *testing.T) {
			if got := getErrorTypeFromStatusCode(tt.statusCode); got != tt.want {
				t.Errorf("getErrorTypeFromStatusCode(%d) = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}

func TestAPIError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	apiErr := NewNetworkError("network failed", "http://example.com", originalErr)

	unwrapped := apiErr.Unwrap()
	if unwrapped != originalErr {
		t.Errorf("APIError.Unwrap() = %v, want %v", unwrapped, originalErr)
	}

	// Test errors.Is
	if !errors.Is(apiErr, originalErr) {
		t.Error("errors.Is should return true for wrapped error")
	}
}

func TestNewAPIErrorFromStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
		url        string
		wantType   ErrorType
	}{
		{
			name:       "404 Not Found",
			statusCode: 404,
			message:    "resource not found",
			url:        "http://example.com/api/users/123",
			wantType:   ErrorTypeServerError,
		},
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
			message:    "internal error",
			url:        "http://example.com/api/submit",
			wantType:   ErrorTypeServerError,
		},
		{
			name:       "304 Not Modified",
			statusCode: 304,
			message:    "not modified",
			url:        "http://example.com/api/data",
			wantType:   ErrorTypeNotModified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAPIErrorFromStatusCode(tt.statusCode, tt.message, tt.url, nil)
			if err.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %v, want %v", err.StatusCode, tt.statusCode)
			}
			if err.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", err.Type, tt.wantType)
			}
			if err.Message != tt.message {
				t.Errorf("Message = %v, want %v", err.Message, tt.message)
			}
			if err.URL != tt.url {
				t.Errorf("URL = %v, want %v", err.URL, tt.url)
			}
		})
	}
}

func TestErrorFactoryFunctions(t *testing.T) {
	tests := []struct {
		name          string
		factoryFunc   func() *APIError
		wantStatus    int
		wantType      ErrorType
		wantServerErr bool
	}{
		{
			name: "NewNetworkError",
			factoryFunc: func() *APIError {
				return NewNetworkError("network error", "http://example.com", nil)
			},
			wantStatus:    0,
			wantType:      ErrorTypeNetworkError,
			wantServerErr: false,
		},
		{
			name: "NewParseError",
			factoryFunc: func() *APIError {
				return NewParseError("parse error", nil)
			},
			wantStatus:    0,
			wantType:      ErrorTypeParseError,
			wantServerErr: false,
		},
		{
			name: "NewNotModifiedError",
			factoryFunc: func() *APIError {
				return NewNotModifiedError()
			},
			wantStatus:    http.StatusNotModified,
			wantType:      ErrorTypeNotModified,
			wantServerErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.factoryFunc()
			if err.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %v, want %v", err.StatusCode, tt.wantStatus)
			}
			if err.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", err.Type, tt.wantType)
			}
			if err.IsServerError() != tt.wantServerErr {
				t.Errorf("IsServerError() = %v, want %v", err.IsServerError(), tt.wantServerErr)
			}
		})
	}
}

func TestAPIError_SpecialMethods(t *testing.T) {
	t.Run("IsNetworkError", func(t *testing.T) {
		err := NewNetworkError("network failed", "", nil)
		if !err.IsNetworkError() {
			t.Error("IsNetworkError() should return true for network error")
		}

		err2 := NewAPIErrorFromStatusCode(500, "server error", "", nil)
		if err2.IsNetworkError() {
			t.Error("IsNetworkError() should return false for non-network error")
		}
	})

	t.Run("IsParseError", func(t *testing.T) {
		err := NewParseError("parse failed", nil)
		if !err.IsParseError() {
			t.Error("IsParseError() should return true for parse error")
		}

		err2 := NewAPIErrorFromStatusCode(500, "server error", "", nil)
		if err2.IsParseError() {
			t.Error("IsParseError() should return false for non-parse error")
		}
	})

	t.Run("IsNotModified", func(t *testing.T) {
		err := NewNotModifiedError()
		if !err.IsNotModified() {
			t.Error("IsNotModified() should return true for 304 error")
		}

		err2 := NewAPIErrorFromStatusCode(304, "not modified", "", nil)
		if !err2.IsNotModified() {
			t.Error("IsNotModified() should return true for 304 status code")
		}

		err3 := NewAPIErrorFromStatusCode(500, "server error", "", nil)
		if err3.IsNotModified() {
			t.Error("IsNotModified() should return false for non-304 error")
		}
	})
}
