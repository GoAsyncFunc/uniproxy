package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// NetworkSettings is the typed form of the panel's networkSettings JSON. Every
// protocol shares the same keys, so the parser lives in the SDK instead of in
// each backend. It normalizes the shapes panel editors emit and reports unknown
// keys; it never decides whether a value is acceptable for a node.
//
// Absent and null fields mean the field is unset, a value of the wrong JSON type
// is an error, and unknown keys are reported rather than rejected.

// HeaderField is one HTTP header with its candidate values; the panel stores a
// value as a string or a list of strings and both forms normalize to a list.
type HeaderField struct {
	Name   string
	Values []string
}

// TCPHeader is the panel's tcp HTTP header obfuscation
// (networkSettings.header.type = "http"). The node matches the request paths and
// hosts and may reuse the response fields.
type TCPHeader struct {
	Type            string
	RequestVersion  string
	RequestPaths    []string
	RequestHosts    []string
	ResponseVersion string
	ResponseStatus  string
	ResponseReason  string
	ResponseHeaders []HeaderField
}

// XHTTPRange is an inclusive range decoded from a JSON number, a single number
// string, a "min-max" string, or the panel's "-1" sentinel.
type XHTTPRange struct{ Min, Max int }

// XHTTPSettings is the allow-listed xhttp extra surface. Absent and null fields
// keep the published panel defaults.
type XHTTPSettings struct {
	Mode             string
	NoGRPCHeader     bool
	NoSSEHeader      bool
	MaxPostBytes     XHTTPRange
	MaxBufferedPosts int
	StreamUpSeconds  XHTTPRange
	PaddingBytes     XHTTPRange
	DownloadPort     int
}

// DefaultXHTTPSettings returns the published panel defaults for absent fields.
func DefaultXHTTPSettings() XHTTPSettings {
	return XHTTPSettings{
		Mode:             "auto",
		MaxPostBytes:     XHTTPRange{Min: 1000000, Max: 1000000},
		MaxBufferedPosts: 30,
		StreamUpSeconds:  XHTTPRange{Min: 20, Max: 80},
		PaddingBytes:     XHTTPRange{Min: 100, Max: 1000},
	}
}

// NetworkSettings is the decoded panel networkSettings value. UnknownKeys holds
// the dotted paths of keys this SDK does not model, sorted.
type NetworkSettings struct {
	Network     string
	Path        string
	Host        string
	ServiceName string
	// MaxEarlyData is nil when unset; an explicit zero remains distinguishable.
	// Limits and defaults are the node's policy, not the SDK's.
	MaxEarlyData        *int
	EarlyDataHeaderName string
	XHTTP               XHTTPSettings
	TCPHeader           *TCPHeader
	UnknownKeys         []string
}

// ParseNetworkSettings decodes networkSettings for one network: tcp, ws,
// httpupgrade, grpc or xhttp. Absent, null and [] mean empty settings. ws and
// xhttp default the path to "/", httpupgrade keeps the panel's value, grpc
// carries only serviceName and no path, and tcp carries the HTTP header. An
// unsupported network name is an error; which networks a node serves is the
// node's decision.
func ParseNetworkSettings(network string, raw json.RawMessage) (NetworkSettings, error) {
	switch network {
	case "tcp":
		header, unknown, err := parsePanelTCPHeader(raw)
		if err != nil {
			return NetworkSettings{Network: network}, err
		}
		return NetworkSettings{Network: network, TCPHeader: header, UnknownKeys: unknown}, nil
	case "xhttp":
		return parsePanelXHTTP(raw)
	case "grpc":
		settings, unknown, err := parsePanelStreamSettings(network, raw)
		if err != nil {
			return NetworkSettings{Network: network}, err
		}
		settings.Path = ""
		settings.UnknownKeys = unknown
		return settings, nil
	case "ws", "httpupgrade":
		settings, unknown, err := parsePanelStreamSettings(network, raw)
		if err != nil {
			return NetworkSettings{Network: network}, err
		}
		settings.UnknownKeys = unknown
		return settings, nil
	default:
		return NetworkSettings{Network: network}, fmt.Errorf("unsupported panel network %q", network)
	}
}

// parsePanelStreamSettings decodes ws, httpupgrade and grpc settings.
func parsePanelStreamSettings(network string, raw json.RawMessage) (NetworkSettings, []string, error) {
	settings := NetworkSettings{Network: network, Path: "/"}
	fields, err := settingsObject(raw)
	if err != nil {
		return NetworkSettings{Network: network}, nil, fmt.Errorf("panel networkSettings must be an object")
	}
	var unknown []string
	for key, value := range fields {
		switch {
		case network == "grpc" && key == "serviceName":
			if settings.ServiceName, err = settingsString(value); err != nil {
				return settings, nil, fmt.Errorf("panel networkSettings serviceName must be a string")
			}
		case network == "grpc":
			unknown = append(unknown, key)
		case network == "ws" && key == "maxEarlyData":
			if json.Unmarshal(value, &settings.MaxEarlyData) != nil {
				return settings, nil, fmt.Errorf("panel networkSettings maxEarlyData must be an integer")
			}
		case network == "ws" && key == "earlyDataHeaderName":
			if json.Unmarshal(value, &settings.EarlyDataHeaderName) != nil {
				return settings, nil, fmt.Errorf("panel networkSettings earlyDataHeaderName must be a string")
			}
		case key == "path":
			if settings.Path, err = settingsString(value); err != nil {
				return settings, nil, fmt.Errorf("panel networkSettings path must be a string")
			}
			if settings.Path == "" {
				settings.Path = "/"
			}
		case network == "httpupgrade" && key == "host":
			if settings.Host, err = settingsString(value); err != nil {
				return settings, nil, fmt.Errorf("panel networkSettings host must be a string")
			}
		case network == "ws" && key == "headers":
			headers, err := settingsObject(value)
			if err != nil {
				return settings, nil, fmt.Errorf("panel networkSettings headers must be an object")
			}
			for name, header := range headers {
				if !strings.EqualFold(name, "Host") {
					unknown = append(unknown, "headers."+name)
					continue
				}
				if settings.Host, err = settingsString(header); err != nil {
					return settings, nil, fmt.Errorf("panel networkSettings headers.%s must be a string", name)
				}
			}
		default:
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return settings, unknown, nil
}

// parsePanelXHTTP decodes the xhttp settings. An empty path, host or mode keeps
// the previous value, matching the panel's own defaults.
func parsePanelXHTTP(raw json.RawMessage) (NetworkSettings, error) {
	settings := NetworkSettings{Network: "xhttp", Path: "/", XHTTP: DefaultXHTTPSettings()}
	fields, err := settingsObject(raw)
	if err != nil {
		return NetworkSettings{Network: "xhttp"}, fmt.Errorf("panel networkSettings must be an object")
	}
	var unknown []string
	for key, value := range fields {
		switch key {
		case "path", "host", "mode":
			text, err := settingsString(value)
			if err != nil {
				return NetworkSettings{Network: "xhttp"}, fmt.Errorf("panel networkSettings %s must be a string", key)
			}
			switch key {
			case "path":
				if text != "" {
					settings.Path = text
				}
			case "host":
				settings.Host = text
			default:
				if text != "" {
					settings.XHTTP.Mode = text
				}
			}
		case "extra":
			extra, err := parsePanelXHTTPExtra(value, &settings.XHTTP)
			if err != nil {
				return NetworkSettings{Network: "xhttp"}, err
			}
			unknown = append(unknown, extra...)
		default:
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	settings.UnknownKeys = unknown
	return settings, nil
}

func parsePanelXHTTPExtra(raw json.RawMessage, x *XHTTPSettings) ([]string, error) {
	fields, err := settingsObject(raw)
	if err != nil {
		return nil, fmt.Errorf("panel networkSettings extra must be an object")
	}
	var unknown []string
	for key, value := range fields {
		known := key == "noGRPCHeader" || key == "noSSEHeader" || key == "scMaxBufferedPosts" ||
			key == "scMaxEachPostBytes" || key == "scStreamUpServerSecs" || key == "xPaddingBytes" || key == "downloadSettings"
		if known && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			// A null field is unset, so the published default stands.
			continue
		}
		switch key {
		case "noGRPCHeader", "noSSEHeader":
			target := &x.NoGRPCHeader
			if key == "noSSEHeader" {
				target = &x.NoSSEHeader
			}
			if json.Unmarshal(value, target) != nil {
				return nil, fmt.Errorf("panel networkSettings extra %s must be a boolean", key)
			}
		case "scMaxBufferedPosts":
			if json.Unmarshal(value, &x.MaxBufferedPosts) != nil {
				return nil, fmt.Errorf("panel networkSettings extra scMaxBufferedPosts must be an integer")
			}
		case "scMaxEachPostBytes", "scStreamUpServerSecs", "xPaddingBytes":
			target := &x.MaxPostBytes
			if key == "scStreamUpServerSecs" {
				target = &x.StreamUpSeconds
			}
			if key == "xPaddingBytes" {
				target = &x.PaddingBytes
			}
			rangeValue, err := parsePanelRange(value)
			if err != nil {
				return nil, err
			}
			*target = rangeValue
		case "downloadSettings":
			download, err := settingsObject(value)
			if err != nil {
				return nil, fmt.Errorf("panel networkSettings extra downloadSettings must be an object")
			}
			for field, setting := range download {
				if field != "port" {
					unknown = append(unknown, "extra.downloadSettings."+field)
					continue
				}
				if json.Unmarshal(setting, &x.DownloadPort) != nil || x.DownloadPort < 1 || x.DownloadPort > 65535 {
					return nil, fmt.Errorf("invalid panel networkSettings extra downloadSettings.port")
				}
			}
		default:
			unknown = append(unknown, "extra."+key)
		}
	}
	sort.Strings(unknown)
	return unknown, nil
}

// parsePanelRange decodes the panel's numeric ranges: a number, a single number
// string, "min-max", or the "-1" sentinel.
func parsePanelRange(raw json.RawMessage) (XHTTPRange, error) {
	var number int
	if json.Unmarshal(raw, &number) == nil {
		return XHTTPRange{Min: number, Max: number}, nil
	}
	var text string
	if json.Unmarshal(raw, &text) != nil || len(text) > 32 {
		return XHTTPRange{}, fmt.Errorf("invalid panel networkSettings range")
	}
	if text == "-1" {
		return XHTTPRange{Min: -1, Max: -1}, nil
	}
	parts := strings.Split(text, "-")
	if len(parts) > 2 {
		return XHTTPRange{}, fmt.Errorf("invalid panel networkSettings range")
	}
	values := make([]int, len(parts))
	for i, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return XHTTPRange{}, fmt.Errorf("invalid panel networkSettings range")
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			return XHTTPRange{}, fmt.Errorf("invalid panel networkSettings range")
		}
		values[i] = value
	}
	if len(values) == 1 {
		return XHTTPRange{Min: values[0], Max: values[0]}, nil
	}
	return XHTTPRange{Min: values[0], Max: values[1]}, nil
}

// parsePanelTCPHeader decodes the tcp HTTP header obfuscation. It returns a nil
// header when the panel sets no header or type "none".
func parsePanelTCPHeader(raw json.RawMessage) (*TCPHeader, []string, error) {
	fields, err := settingsObject(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("panel networkSettings must be an object")
	}
	var unknown []string
	var header map[string]json.RawMessage
	for key, value := range fields {
		if key != "header" {
			unknown = append(unknown, key)
			continue
		}
		if settingsEmpty(value) {
			continue
		}
		if header, err = settingsObject(value); err != nil {
			return nil, nil, fmt.Errorf("panel networkSettings header must be an object")
		}
	}
	if header == nil {
		sort.Strings(unknown)
		return nil, unknown, nil
	}
	kind, err := settingsString(header["type"])
	if err != nil {
		return nil, nil, fmt.Errorf("panel networkSettings header.type must be a string")
	}
	switch kind {
	case "", "none":
		for key := range header {
			if key != "type" {
				unknown = append(unknown, "header."+key)
			}
		}
		sort.Strings(unknown)
		return nil, unknown, nil
	case "http":
	default:
		return nil, nil, fmt.Errorf("unsupported panel networkSettings header.type")
	}
	result := &TCPHeader{Type: kind}
	for key, value := range header {
		switch key {
		case "type":
		case "request":
			extra, err := parsePanelTCPRequest(value, result)
			if err != nil {
				return nil, nil, err
			}
			unknown = append(unknown, extra...)
		case "response":
			extra, err := parsePanelTCPResponse(value, result)
			if err != nil {
				return nil, nil, err
			}
			unknown = append(unknown, extra...)
		default:
			unknown = append(unknown, "header."+key)
		}
	}
	sort.Strings(unknown)
	return result, unknown, nil
}

func parsePanelTCPRequest(raw json.RawMessage, header *TCPHeader) ([]string, error) {
	if settingsEmpty(raw) {
		return nil, nil
	}
	request, err := settingsObject(raw)
	if err != nil {
		return nil, fmt.Errorf("panel networkSettings header.request must be an object")
	}
	var unknown []string
	for key, value := range request {
		switch key {
		case "version":
			if header.RequestVersion, err = settingsString(value); err != nil {
				return nil, fmt.Errorf("panel networkSettings header.request.version must be a string")
			}
		case "method":
			// Client behaviour; decoded for shape only.
			if _, err = settingsString(value); err != nil {
				return nil, fmt.Errorf("panel networkSettings header.request.method must be a string")
			}
		case "path":
			if header.RequestPaths, err = settingsStringList(value); err != nil {
				return nil, fmt.Errorf("panel networkSettings header.request.path must be a string or a list")
			}
		case "headers":
			if settingsEmpty(value) {
				continue
			}
			headers, err := settingsObject(value)
			if err != nil {
				return nil, fmt.Errorf("panel networkSettings header.request.headers must be an object")
			}
			for name, values := range headers {
				if !strings.EqualFold(name, "Host") {
					unknown = append(unknown, "header.request.headers."+name)
					continue
				}
				list, err := settingsStringList(values)
				if err != nil {
					return nil, fmt.Errorf("panel networkSettings header.request.headers.%s must be a string or a list", name)
				}
				header.RequestHosts = append(header.RequestHosts, list...)
			}
		default:
			unknown = append(unknown, "header.request."+key)
		}
	}
	sort.Strings(unknown)
	return unknown, nil
}

func parsePanelTCPResponse(raw json.RawMessage, header *TCPHeader) ([]string, error) {
	if settingsEmpty(raw) {
		return nil, nil
	}
	response, err := settingsObject(raw)
	if err != nil {
		return nil, fmt.Errorf("panel networkSettings header.response must be an object")
	}
	var unknown []string
	for key, value := range response {
		switch key {
		case "version", "status", "reason":
			text, err := settingsString(value)
			if err != nil {
				return nil, fmt.Errorf("panel networkSettings header.response.%s must be a string", key)
			}
			switch key {
			case "version":
				header.ResponseVersion = text
			case "status":
				header.ResponseStatus = text
			default:
				header.ResponseReason = text
			}
		case "headers":
			if settingsEmpty(value) {
				continue
			}
			headers, err := settingsObject(value)
			if err != nil {
				return nil, fmt.Errorf("panel networkSettings header.response.headers must be an object")
			}
			for name, values := range headers {
				list, err := settingsStringList(values)
				if err != nil {
					return nil, fmt.Errorf("panel networkSettings header.response.headers.%s must be a string or a list", name)
				}
				header.ResponseHeaders = append(header.ResponseHeaders, HeaderField{Name: name, Values: list})
			}
			sort.Slice(header.ResponseHeaders, func(i, j int) bool {
				return header.ResponseHeaders[i].Name < header.ResponseHeaders[j].Name
			})
		default:
			unknown = append(unknown, "header.response."+key)
		}
	}
	sort.Strings(unknown)
	return unknown, nil
}
