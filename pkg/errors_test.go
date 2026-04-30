package pkg

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	resty "github.com/go-resty/resty/v2"
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

func TestAPIError_ErrorRedactsSensitiveQueryValues(t *testing.T) {
	err := NewNetworkError(
		"request failed",
		"https://api.example.com/config?token=secret-token&key=secret-key&auth=secret-auth&authorization=secret-bearer&node_id=1",
		nil,
	)

	got := err.Error()
	for _, secret := range []string{"secret-token", "secret-key", "secret-auth", "secret-bearer"} {
		if strings.Contains(got, secret) {
			t.Fatalf("error leaked %q in %q", secret, got)
		}
	}
	for _, redacted := range []string{"token=REDACTED", "key=REDACTED", "auth=REDACTED", "authorization=REDACTED", "node_id=1"} {
		if !strings.Contains(got, redacted) {
			t.Fatalf("error = %q, want to contain %q", got, redacted)
		}
	}
}

func TestAPIError_ErrorRedactsMixedCaseMLDSASeedQueryValue(t *testing.T) {
	apiErr := NewAPIError(
		http.StatusBadGateway,
		ErrorTypeServerError,
		"request failed",
		"https://api.example.com/config?mldsa65Seed=seed-secret&node_id=1",
		nil,
	)

	for name, value := range map[string]string{
		"Error": apiErr.Error(),
		"URL":   apiErr.URL,
	} {
		if strings.Contains(value, "seed-secret") {
			t.Fatalf("%s leaked seed secret in %q", name, value)
		}
		if !strings.Contains(value, "mldsa65Seed=REDACTED") {
			t.Fatalf("%s = %q, want mldsa65Seed=REDACTED", name, value)
		}
	}
}

func TestAPIError_ErrorRedactsUserInfoAndCommonSecretQueryValues(t *testing.T) {
	err := NewNetworkError(
		"request failed",
		"https://user:password@example.com/config?access_token=aaa111&api_key=bbb222&client_secret=ccc333&password=ddd444&sig=eee555&node_id=1",
		nil,
	)

	got := err.Error()
	for _, secret := range []string{"user:password", "aaa111", "bbb222", "ccc333", "ddd444", "eee555"} {
		if strings.Contains(got, secret) {
			t.Fatalf("error leaked %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "node_id=1") {
		t.Fatalf("error = %q, want node_id preserved", got)
	}
}

func TestSanitizeErrorRedactsEmbeddedSecrets(t *testing.T) {
	tests := []struct {
		name   string
		error  error
		secret string
	}{
		{
			name:   "username password userinfo",
			error:  errors.New(`Get "https://user:password@api.example.com/path?token=secret-token&node_id=1": connection refused`),
			secret: "user:password",
		},
		{
			name:   "username only userinfo",
			error:  errors.New(`Get "https://secret-token@api.example.com/path?node_id=1": connection refused`),
			secret: "secret-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeError(tt.error).Error()
			if strings.Contains(got, tt.secret) {
				t.Fatalf("error leaked %q in %q", tt.secret, got)
			}
			if !strings.Contains(got, "https://REDACTED@api.example.com") || !strings.Contains(got, "node_id=1") {
				t.Fatalf("error = %q", got)
			}
		})
	}
}

func TestRedactEmbeddedSecretsCoversDirectFormats(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		secret string
	}{
		{name: "bearer query", input: "authorization=Bearer secret-token", secret: "secret-token"},
		{name: "json authorization", input: `{"authorization":"Bearer secret-token"}`, secret: "secret-token"},
		{name: "json client secret", input: `{"client_secret":"secret-token"}`, secret: "secret-token"},
		{name: "json mldsa seed", input: `{"mldsa65Seed":"seed-secret"}`, secret: "seed-secret"},
		{name: "json password with spaces", input: `{"password":"correct horse battery staple"}`, secret: "horse battery staple"},
		{name: "json password with escaped quote", input: `{"password":"prefix \"remaining secret with spaces"}`, secret: "remaining secret with spaces"},
		{name: "json password with apostrophe", input: `{"password":"prefix 'remaining secret with spaces"}`, secret: "remaining secret with spaces"},
		{name: "x api key query", input: "x-api-key=secret-token", secret: "secret-token"},
		{name: "url userinfo", input: "https://user:password@example.com/config", secret: "user:password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactEmbeddedSecrets(tt.input)
			if strings.Contains(got, tt.secret) {
				t.Fatalf("redacted value leaked %q in %q", tt.secret, got)
			}
			if !strings.Contains(got, "REDACTED") {
				t.Fatalf("redacted value = %q, want REDACTED", got)
			}
		})
	}
}

func TestSanitizeAPIErrorMessageRedactsAndTruncates(t *testing.T) {
	secret := "secret-token"
	message := "token=" + secret + "&" + strings.Repeat("a", maxAPIErrorMessageBytes+100)

	got := sanitizeAPIErrorMessage(message)
	if strings.Contains(got, secret) {
		t.Fatalf("message leaked secret in %q", got)
	}
	if !strings.Contains(got, "token=REDACTED") {
		t.Fatalf("message = %q, want redacted token", got)
	}
	if !strings.Contains(got, "[truncated]") {
		t.Fatalf("message = %q, want truncation marker", got)
	}
}

func TestAPIErrorConstructorsRedactMessage(t *testing.T) {
	message := `panel failed with token=secret-token, mldsa65seed=secret-seed-query, {"client_secret":"secret-client"}, and {"mldsa65seed":"secret-seed-json"}`
	tests := []struct {
		name string
		err  *APIError
	}{
		{name: "business logic", err: NewBusinessLogicError(message, "https://example.com")},
		{name: "api error", err: NewAPIError(http.StatusBadGateway, ErrorTypeServerError, message, "https://example.com", nil)},
		{name: "status code", err: NewAPIErrorFromStatusCode(http.StatusBadGateway, message, "https://example.com", nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for name, value := range map[string]string{
				"Message":  tt.err.Message,
				"Error":    tt.err.Error(),
				"GoString": fmt.Sprintf("%#v", tt.err),
			} {
				for _, secret := range []string{"secret-token", "secret-seed-query", "secret-client", "secret-seed-json"} {
					if strings.Contains(value, secret) {
						t.Fatalf("%s leaked %q in %q", name, secret, value)
					}
				}
			}
		})
	}
}

func TestNewBusinessLogicErrorRedactsURL(t *testing.T) {
	err := NewBusinessLogicError("failed", "https://user:password@example.com/config?client_secret=secret-token&x-api-key=secret-key&node_id=1")

	for name, value := range map[string]string{
		"URL":      err.URL,
		"Error":    err.Error(),
		"GoString": fmt.Sprintf("%#v", err),
	} {
		for _, secret := range []string{"user:password", "secret-token", "secret-key"} {
			if strings.Contains(value, secret) {
				t.Fatalf("%s leaked %q in %q", name, secret, value)
			}
		}
		if !strings.Contains(value, "REDACTED") {
			t.Fatalf("%s = %q, want REDACTED", name, value)
		}
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
	if unwrapped == nil || unwrapped.Error() != originalErr.Error() {
		t.Errorf("APIError.Unwrap() = %v, want message %q", unwrapped, originalErr.Error())
	}

}

func TestAPIError_UnwrapRedactsSensitiveOriginalError(t *testing.T) {
	originalErr := errors.New(`Get "https://api.example.com/config?token=secret-token&node_id=1": connection refused`)
	apiErr := NewNetworkError("network failed", "https://api.example.com/config?token=secret-token&node_id=1", originalErr)

	for name, err := range map[string]error{
		"Err field": apiErr.Err,
		"Unwrap":    apiErr.Unwrap(),
	} {
		if err == nil {
			t.Fatalf("%s is nil", name)
		}
		if strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("%s leaked token in %q", name, err.Error())
		}
		if !strings.Contains(err.Error(), "token=REDACTED") {
			t.Fatalf("%s = %q, want redacted token", name, err.Error())
		}
		if unwrapped := errors.Unwrap(err); unwrapped != nil {
			t.Fatalf("%s exposed nested unwrap %q", name, unwrapped.Error())
		}
	}

	for name, value := range map[string]string{
		"Err field GoString": fmt.Sprintf("%#v", apiErr.Err),
		"APIError GoString":  fmt.Sprintf("%#v", apiErr),
	} {
		if strings.Contains(value, "secret-token") {
			t.Fatalf("%s leaked token in %q", name, value)
		}
	}

	if errors.Is(apiErr, originalErr) {
		t.Error("errors.Is should not expose arbitrary sensitive original errors")
	}
}

func TestAPIError_PreservesSafeSentinelMatching(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{name: "context canceled", err: context.Canceled, target: context.Canceled},
		{name: "deadline exceeded", err: context.DeadlineExceeded, target: context.DeadlineExceeded},
		{name: "response body too large", err: resty.ErrResponseBodyTooLarge, target: resty.ErrResponseBodyTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := NewNetworkError("network failed", "https://api.example.com/config?token=secret-token", tt.err)
			if !errors.Is(apiErr, tt.target) {
				t.Fatalf("errors.Is(apiErr, %v) = false", tt.target)
			}
			if strings.Contains(fmt.Sprintf("%#v", apiErr), "secret-token") {
				t.Fatalf("GoString leaked token: %#v", apiErr)
			}
		})
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
