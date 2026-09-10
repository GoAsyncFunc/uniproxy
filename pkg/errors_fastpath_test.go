package pkg

import (
	"strings"
	"testing"
)

// Pre-optimization replacement sequence; intentionally no delimiter guards.
func originalRedactEmbeddedSecrets(value string) string {
	value = embeddedURLUserinfoPattern.ReplaceAllString(value, "${1}REDACTED@")
	value = embeddedBearerColonPattern.ReplaceAllString(value, "${1}REDACTED")
	value = embeddedBearerQueryPattern.ReplaceAllString(value, "${1}REDACTED")
	value = embeddedSecretDoubleQuotedColonPattern.ReplaceAllString(value, "${1}REDACTED")
	value = embeddedSecretSingleQuotedColonPattern.ReplaceAllString(value, "${1}REDACTED")
	value = embeddedSecretColonPattern.ReplaceAllString(value, "${1}REDACTED")
	return embeddedSecretQueryPattern.ReplaceAllString(value, "$1=REDACTED")
}

func TestRedactionFastPathEquivalent(t *testing.T) {
	inputs := []string{"", "plain text", "email@example.com", "http://example.com", "http://user:pass@example.com/?token=secret", "authorization: Bearer secret", "auth=Bearer secret", `{"token":"a=b:c@d"}`, "password: 'secret'", "Key=secret", "ſecret: secret", "TOKEN=secret", strings.Repeat("x", 8192), strings.Repeat("token=x&", 1024), "\xff:token=secret"}
	for _, input := range inputs {
		if got, want := redactEmbeddedSecrets(input), originalRedactEmbeddedSecrets(input); got != want {
			t.Fatalf("redaction mismatch for synthetic input %q", input)
		}
	}
	for _, key := range []string{"token", "key", "authorization", "private_key", "access_token", "password", "signature", "mldsa65seed", "Key", "ſecret"} {
		for _, sep := range []string{"=", ":", ": ", " : '"} {
			input := key + sep + "fixture-secret"
			if got, want := redactEmbeddedSecrets(input), originalRedactEmbeddedSecrets(input); got != want {
				t.Fatalf("mismatch for %q", input)
			}
		}
	}
}

func FuzzRedactionFastPathEquivalent(f *testing.F) {
	for _, input := range []string{"plain text", "token=x", `{"password":"a=b:c"}`, "auth=Bearer x", "https://u:p@example.com", "Key=x", "ſecret: x", "\xff"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxAPIErrorMessageBytes {
			return
		}
		if got, want := redactEmbeddedSecrets(input), originalRedactEmbeddedSecrets(input); got != want {
			t.Fatal("redaction differs from original")
		}
		// Check length-cap behavior after replacements expand small secrets.
		want := originalRedactEmbeddedSecrets(input)
		if len(want) > maxAPIErrorMessageBytes {
			want = want[:maxAPIErrorMessageBytes] + "... [truncated]"
		}
		if sanitizeAPIErrorMessage(input) != want {
			t.Fatal("sanitization differs from original")
		}
	})
}

func BenchmarkRedactionFastPath(b *testing.B) {
	for _, implementation := range []struct {
		name string
		fn   func(string) string
	}{{"original", originalRedactEmbeddedSecrets}, {"guarded", redactEmbeddedSecrets}} {
		for _, input := range []struct{ name, body string }{{"plain", strings.Repeat("x", 8192)}, {"query", strings.Repeat("token=x&", 1024)}, {"colon", `{"token":"` + strings.Repeat("x", 8182)}, {"mixed", strings.Repeat("token=x&password: y ", 400)}} {
			b.Run(implementation.name+"/"+input.name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchmarkSanitizedMessage = implementation.fn(input.body)
				}
			})
		}
	}
}
