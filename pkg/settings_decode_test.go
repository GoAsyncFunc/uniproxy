package pkg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSettingsEmpty(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want bool
	}{
		{"", true},
		{"null", true},
		{"[]", true},
		{" [] ", true},
		{"{}", false},
		{`""`, false},
		{"0", false},
		{`{"a":1}`, false},
	} {
		if got := settingsEmpty(json.RawMessage(test.raw)); got != test.want {
			t.Errorf("settingsEmpty(%q) = %t, want %t", test.raw, got, test.want)
		}
	}
}

func TestSettingsObject(t *testing.T) {
	for _, raw := range []string{"", "null", "[]"} {
		fields, err := settingsObject(json.RawMessage(raw))
		if err != nil || len(fields) != 0 {
			t.Fatalf("settingsObject(%q) = %v, %v", raw, fields, err)
		}
	}
	fields, err := settingsObject(json.RawMessage(`{"a":1,"b":null}`))
	if err != nil || len(fields) != 2 {
		t.Fatalf("settingsObject object = %v, %v", fields, err)
	}
	for _, raw := range []string{`[1]`, `"x"`, "1", "true"} {
		if _, err := settingsObject(json.RawMessage(raw)); err == nil {
			t.Errorf("settingsObject(%q) accepted", raw)
		}
	}
}

func TestSettingsString(t *testing.T) {
	for _, raw := range []string{"", "null", "[]"} {
		text, err := settingsString(json.RawMessage(raw))
		if err != nil || text != "" {
			t.Fatalf("settingsString(%q) = %q, %v", raw, text, err)
		}
	}
	if text, err := settingsString(json.RawMessage(`"a"`)); err != nil || text != "a" {
		t.Fatalf("settingsString string = %q, %v", text, err)
	}
	for _, raw := range []string{"1", "true", "{}", `[1]`} {
		if _, err := settingsString(json.RawMessage(raw)); err == nil {
			t.Errorf("settingsString(%q) accepted", raw)
		}
	}
}

func TestSettingsStringOrNumber(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"null", ""},
		{"[]", ""},
		{`"443"`, "443"},
		{"443", "443"},
		{"443.5", "443.5"},
		{"-1", "-1"},
	} {
		text, err := settingsStringOrNumber(json.RawMessage(test.raw))
		if err != nil || text != test.want {
			t.Errorf("settingsStringOrNumber(%q) = %q, %v; want %q", test.raw, text, err, test.want)
		}
	}
	for _, raw := range []string{"true", "{}", `[1]`} {
		if _, err := settingsStringOrNumber(json.RawMessage(raw)); err == nil {
			t.Errorf("settingsStringOrNumber(%q) accepted", raw)
		}
	}
}

func TestSettingsStringList(t *testing.T) {
	for _, raw := range []string{"", "null", "[]"} {
		list, err := settingsStringList(json.RawMessage(raw))
		if err != nil || len(list) != 0 {
			t.Fatalf("settingsStringList(%q) = %v, %v", raw, list, err)
		}
	}
	if list, err := settingsStringList(json.RawMessage(`"a"`)); err != nil || len(list) != 1 || list[0] != "a" {
		t.Fatalf("settingsStringList string = %v, %v", list, err)
	}
	if list, err := settingsStringList(json.RawMessage(`["a","b"]`)); err != nil || len(list) != 2 || list[1] != "b" {
		t.Fatalf("settingsStringList list = %v, %v", list, err)
	}
	for _, raw := range []string{"1", "{}", `[1]`} {
		if _, err := settingsStringList(json.RawMessage(raw)); err == nil {
			t.Errorf("settingsStringList(%q) accepted", raw)
		}
	}
}

func TestSettingsXver(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want uint64
	}{
		{"", 0},
		{"null", 0},
		{"0", 0},
		{"1", 1},
		{"2", 2},
		{`"0"`, 0},
		{`"1"`, 1},
		{`"2"`, 2},
		{" 1 ", 1},
	} {
		got, err := settingsXver(json.RawMessage(test.raw))
		if err != nil || got != test.want {
			t.Errorf("settingsXver(%q) = %d, %v; want %d", test.raw, got, err, test.want)
		}
	}
	for _, raw := range []string{"3", "-1", "1.5", "true", "{}", "[]", `""`, `"null"`, `"bad"`, `"3"`, "18446744073709551616"} {
		if _, err := settingsXver(json.RawMessage(raw)); err == nil {
			t.Errorf("settingsXver(%q) accepted", raw)
		}
	}
}

func TestSettingsBase64URL(t *testing.T) {
	raw := []byte{0, 1, 2, 250, 251, 252}
	for _, text := range []string{
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	} {
		decoded, err := settingsBase64URL(text)
		if err != nil || !bytes.Equal(decoded, raw) {
			t.Errorf("settingsBase64URL(%q) = %v, %v", text, decoded, err)
		}
	}
	for _, text := range []string{"a+b/", "not base64!", "=", "a"} {
		if _, err := settingsBase64URL(text); err == nil {
			t.Errorf("settingsBase64URL(%q) accepted", text)
		}
	}
}
