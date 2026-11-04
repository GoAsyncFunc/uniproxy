package pkg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

// The panel and its editors emit the same logical value in several shapes:
// untouched settings arrive as an empty PHP array, numbers arrive as strings,
// and header values arrive as a string or a list. These helpers normalize the
// shapes only. They never decide whether a value is acceptable for a node;
// that policy belongs to each node implementation.

const x25519KeySize = 32

// settingsEmpty reports whether raw is absent, null, or the empty array the
// panel writes for untouched settings.
func settingsEmpty(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("[]"))
}

// settingsObject decodes a settings object. Absent, null and [] are an empty
// object; a non-empty array or a scalar is an error.
func settingsObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if settingsEmpty(raw) {
		return map[string]json.RawMessage{}, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("expected a JSON object")
	}
	return fields, nil
}

// settingsString decodes a string. Absent and null are an empty string.
func settingsString(raw json.RawMessage) (string, error) {
	if settingsEmpty(raw) {
		return "", nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", fmt.Errorf("expected a string")
	}
	return text, nil
}

// settingsStringOrNumber decodes a string or a JSON number as text. Numbers
// keep their literal form; callers apply their own numeric rules.
func settingsStringOrNumber(raw json.RawMessage) (string, error) {
	if settingsEmpty(raw) {
		return "", nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String(), nil
	}
	return "", fmt.Errorf("expected a string or a number")
}

// settingsStringList decodes a string or a list of strings. Absent and null are
// an empty list.
func settingsStringList(raw json.RawMessage) ([]string, error) {
	if settingsEmpty(raw) {
		return nil, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return []string{text}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("expected a string or a list of strings")
	}
	return list, nil
}

// settingsXver decodes the panel's xver field as an unsigned integer or an
// integer string from 0 to 2. Absent and null mean 0; any other shape is an
// error, including quoted non-integers and arrays.
func settingsXver(raw json.RawMessage) (uint64, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return 0, nil
	}
	if value[0] == '"' {
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return 0, fmt.Errorf("xver must be an integer between 0 and 2")
		}
		value = []byte(text)
	}
	parsed, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil || parsed > 2 {
		return 0, fmt.Errorf("xver must be an integer between 0 and 2")
	}
	return parsed, nil
}

// settingsBase64URL decodes base64url text with or without padding.
func settingsBase64URL(text string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(text); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(text)
}
