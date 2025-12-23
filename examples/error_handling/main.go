package main

import (
	"errors"
	"fmt"

	"github.com/GoAsyncFunc/uniproxy/pkg"
)

func main() {
	// Simulate different types of errors
	demonstrateErrors()
}

func demonstrateErrors() {
	fmt.Println("=== Error Handling Examples ===")

	// Example 1: Server Error (401)
	err1 := pkg.NewAPIErrorFromStatusCode(401, "invalid token", "http://api.example.com/users", nil)
	handleError("Example 1: 401 Unauthorized", err1)

	// Example 2: Server Error (404)
	err2 := pkg.NewAPIErrorFromStatusCode(404, "user not found", "http://api.example.com/users/123", nil)
	handleError("Example 2: 404 Not Found", err2)

	// Example 3: Server Error (500)
	err3 := pkg.NewAPIErrorFromStatusCode(500, "database connection failed", "http://api.example.com/data", nil)
	handleError("Example 3: 500 Internal Server Error", err3)

	// Example 4: Server Error (503)
	err4 := pkg.NewAPIErrorFromStatusCode(503, "service temporarily unavailable", "http://api.example.com/service", nil)
	handleError("Example 4: 503 Service Unavailable", err4)

	// Example 5: Network Error
	err5 := pkg.NewNetworkError("connection timeout", "http://api.example.com", nil)
	handleError("Example 5: Network Error", err5)

	// Example 6: Parse Error
	err6 := pkg.NewParseError("invalid JSON response", nil)
	handleError("Example 6: Parse Error", err6)

	// Example 7: 304 Not Modified
	err7 := pkg.NewNotModifiedError()
	handleError("Example 7: 304 Not Modified", err7)

	// Example 8: Error Chain
	originalErr := errors.New("connection refused")
	err8 := pkg.NewNetworkError("unable to connect to server", "http://api.example.com", originalErr)
	handleErrorWithChain("Example 8: Network Error with Chain", err8)
}

func handleError(title string, err error) {
	fmt.Printf("--- %s ---\n", title)

	var apiErr *pkg.APIError
	if errors.As(err, &apiErr) {
		// Output basic info
		fmt.Printf("Error: %s\n", apiErr.Error())
		fmt.Printf("Status Code: %d\n", apiErr.StatusCode)
		fmt.Printf("Error Type: %s\n", apiErr.Type)
		fmt.Printf("Message: %s\n", apiErr.Message)

		// Determine error category
		if apiErr.IsServerError() {
			fmt.Println("✗ This is a Server Error")
			fmt.Println("  Recommendation: Retry later or contact admin")
			fmt.Println("  Retryable: Yes")
		} else if apiErr.IsNetworkError() {
			fmt.Println("✗ This is a Network Error")
			fmt.Println("  Recommendation: Check network connection")
			fmt.Println("  Retryable: Yes")
		} else if apiErr.IsParseError() {
			fmt.Println("✗ This is a Parse Error")
			fmt.Println("  Recommendation: Check API version compatibility")
			fmt.Println("  Retryable: No")
		} else if apiErr.IsNotModified() {
			fmt.Println("ℹ Data Not Modified")
			fmt.Println("  Recommendation: Use cached data")
			fmt.Println("  Retryable: No")
		}
	}

	fmt.Println()
}

func handleErrorWithChain(title string, err error) {
	fmt.Printf("--- %s ---\n", title)

	var apiErr *pkg.APIError
	if errors.As(err, &apiErr) {
		fmt.Printf("Error: %s\n", apiErr.Error())

		// Check error chain
		if apiErr.Err != nil {
			fmt.Printf("Original Error: %v\n", apiErr.Err)
			fmt.Println("✓ Contains error chain for debugging")
		}
	}

	fmt.Println()
}
