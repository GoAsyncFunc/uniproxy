package pkg

import (
	"regexp"
	"strings"
	"testing"
)

// Keep the pre-optimization expression as an independent compatibility oracle.
var originalUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

const sampleUUID = "550e8400-e29b-41d4-a716-446655440000"

func TestValidUserUUIDContract(t *testing.T) {
	for _, value := range []string{sampleUUID, strings.ToUpper(sampleUUID), "00000000-0000-1000-8000-000000000000", "ffffffff-ffff-8fff-bfff-ffffffffffff"} {
		if !validUserUUID(value) {
			t.Fatalf("rejected valid UUID %q", value)
		}
	}
	for _, value := range []string{"", sampleUUID + "\n", " " + sampleUUID, sampleUUID + " ", "{" + sampleUUID + "}", "urn:uuid:" + sampleUUID, strings.ReplaceAll(sampleUUID, "-", ""), "00000000-0000-0000-0000-000000000000", strings.Repeat("é", 18)} {
		if validUserUUID(value) {
			t.Fatalf("accepted invalid UUID %q", value)
		}
	}
	// Exhaust every single-byte substitution, including invalid UTF-8.
	for i := 0; i < len(sampleUUID); i++ {
		for c := 0; c < 256; c++ {
			value := []byte(sampleUUID)
			value[i] = byte(c)
			assertUUIDEquivalent(t, string(value))
		}
	}
	for version := byte('0'); version <= '9'; version++ {
		for _, variant := range []byte("0123456789abcdefABCDEF") {
			value := []byte(sampleUUID)
			value[14] = version
			value[19] = variant
			assertUUIDEquivalent(t, string(value))
		}
	}
}

func assertUUIDEquivalent(t *testing.T, value string) {
	t.Helper()
	if got, want := validUserUUID(value), originalUUIDPattern.MatchString(value); got != want {
		t.Fatalf("UUID %q: got %t, want %t", value, got, want)
	}
}

func FuzzValidUserUUIDMatchesOriginal(f *testing.F) {
	for _, value := range []string{"", sampleUUID, strings.ToUpper(sampleUUID), sampleUUID + "\n", "00000000-0000-0000-0000-000000000000", strings.Repeat("\xff", 36)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		assertUUIDEquivalent(t, value)
		// Also explore near-valid inputs; arbitrary strings often fail length alone.
		candidate := []byte(sampleUUID)
		for i := 0; i+1 < len(value) && i < 72; i += 2 {
			candidate[int(value[i])%len(candidate)] = value[i+1]
		}
		assertUUIDEquivalent(t, string(candidate))
	})
}

func TestUserUUIDCaseInsensitiveDuplicates(t *testing.T) {
	users := &UserListBody{Users: []UserInfo{{Id: 1, Uuid: sampleUUID}, {Id: 2, Uuid: strings.ToUpper(sampleUUID)}}}
	err := validateUserList(users)
	if err == nil || err.Error() != "duplicate user uuid for id 2" {
		t.Fatalf("unexpected duplicate result: %v", err)
	}
	if users.Users[0].Uuid != sampleUUID || users.Users[1].Uuid != strings.ToUpper(sampleUUID) {
		t.Fatal("validation mutated UUIDs")
	}
}

var benchmarkUUIDValid bool

func BenchmarkUUIDValidation(b *testing.B) {
	for _, implementation := range []struct {
		name     string
		validate func(string) bool
	}{{"original_regexp", originalUUIDPattern.MatchString}, {"ascii", validUserUUID}} {
		for _, input := range []struct{ name, value string }{{"valid", sampleUUID}, {"uppercase", strings.ToUpper(sampleUUID)}, {"invalid_tail", sampleUUID[:35] + "!"}} {
			b.Run(implementation.name+"/"+input.name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchmarkUUIDValid = implementation.validate(input.value)
				}
			})
		}
	}
}
