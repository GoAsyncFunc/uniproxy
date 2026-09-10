package pkg

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

var benchmarkUsers []UserInfo
var benchmarkHash [32]byte

// These benchmarks exclude HTTP and fixture creation so decode, validation,
// hashing and copy costs can be measured independently.
func BenchmarkUserPipeline(b *testing.B) {
	for _, count := range []int{10000, 50000} {
		b.Run(fmt.Sprintf("users_%d", count), func(b *testing.B) {
			body := []byte(benchmarkUserListBody(count))
			var parsed UserListBody
			if err := json.Unmarshal(body, &parsed); err != nil {
				b.Fatal(err)
			}
			if err := validateUserList(&parsed); err != nil {
				b.Fatal(err)
			}
			b.Run("decode", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var result UserListBody
					if err := json.Unmarshal(body, &result); err != nil {
						b.Fatal(err)
					}
					benchmarkUsers = result.Users
				}
			})
			b.Run("validate", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := validateUserList(&parsed); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("hash", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchmarkHash = sha256.Sum256(body)
				}
			})
			b.Run("copy", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchmarkUsers = cloneUserInfos(parsed.Users)
				}
			})
		})
	}
}

func BenchmarkErrorRedactionInputs(b *testing.B) {
	for _, tc := range []struct{ name, body string }{
		{"plain_8KiB", strings.Repeat("x", maxAPIErrorMessageBytes)},
		{"secrets_8KiB", strings.Repeat("token=x&", maxAPIErrorMessageBytes/8)},
		{"unterminated_quote", `{"token":"` + strings.Repeat("x", maxAPIErrorMessageBytes-10)},
		{"oversized", strings.Repeat("x", maxAPIErrorMessageBytes+1)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmarkSanitizedMessage = sanitizeAPIErrorMessage(tc.body)
			}
		})
	}
}
