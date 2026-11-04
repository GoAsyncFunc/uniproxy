package pkg

import (
	"encoding/json"
	"reflect"
	"testing"
)

func parseNetwork(t *testing.T, network, raw string) NetworkSettings {
	t.Helper()
	settings, err := ParseNetworkSettings(network, json.RawMessage(raw))
	if err != nil {
		t.Fatalf("ParseNetworkSettings(%s, %s) = %v", network, raw, err)
	}
	return settings
}

func TestParseNetworkSettingsEmptyShapes(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "httpupgrade", "grpc", "xhttp"} {
		for _, raw := range []string{"", "null", "[]"} {
			t.Run(network+"/"+raw, func(t *testing.T) {
				settings := parseNetwork(t, network, raw)
				if len(settings.UnknownKeys) != 0 {
					t.Fatalf("unexpected unknown keys: %v", settings.UnknownKeys)
				}
				wantPath := "/"
				if network == "grpc" || network == "tcp" {
					wantPath = ""
				}
				if settings.Path != wantPath || settings.Host != "" || settings.ServiceName != "" {
					t.Fatalf("unexpected settings: %+v", settings)
				}
				if network == "tcp" && settings.TCPHeader != nil {
					t.Fatalf("unexpected header: %+v", settings.TCPHeader)
				}
				if network == "xhttp" && !reflect.DeepEqual(settings.XHTTP, DefaultXHTTPSettings()) {
					t.Fatalf("unexpected xhttp settings: %+v", settings.XHTTP)
				}
			})
		}
	}
}

func TestParseNetworkSettingsUnsupportedNetwork(t *testing.T) {
	for _, network := range []string{"", "quic", "http2", "splithttp"} {
		if _, err := ParseNetworkSettings(network, json.RawMessage(`{}`)); err == nil {
			t.Errorf("network %q accepted", network)
		}
	}
}

func TestParseNetworkSettingsWS(t *testing.T) {
	settings := parseNetwork(t, "ws", `{"path":"/vless","headers":{"Host":"cover.example"}}`)
	if settings.Path != "/vless" || settings.Host != "cover.example" {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	settings = parseNetwork(t, "ws", `{"headers":{"host":"cover.example","X-Extra":["a"]}}`)
	if settings.Host != "cover.example" || !reflect.DeepEqual(settings.UnknownKeys, []string{"headers.X-Extra"}) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	settings = parseNetwork(t, "ws", `{"path":"","headers":{"Host":[]},"serviceName":"ignored"}`)
	if settings.Path != "/" || settings.Host != "" || !reflect.DeepEqual(settings.UnknownKeys, []string{"serviceName"}) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	settings = parseNetwork(t, "ws", `{"headers":{"Extra":3}}`)
	if !reflect.DeepEqual(settings.UnknownKeys, []string{"headers.Extra"}) {
		t.Fatalf("unknown keys = %v", settings.UnknownKeys)
	}
	for _, raw := range []string{`{"path":3}`, `{"path":{}}`, `{"headers":1}`, `{"headers":[1]}`} {
		if _, err := ParseNetworkSettings("ws", json.RawMessage(raw)); err == nil {
			t.Errorf("ws %s accepted", raw)
		}
	}
}

func TestParseNetworkSettingsHTTPUpgrade(t *testing.T) {
	settings := parseNetwork(t, "httpupgrade", `{"path":"/up","host":"cover.example"}`)
	if settings.Path != "/up" || settings.Host != "cover.example" {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	settings = parseNetwork(t, "httpupgrade", `{"path":null,"host":null,"extra":1}`)
	if settings.Path != "/" || settings.Host != "" || !reflect.DeepEqual(settings.UnknownKeys, []string{"extra"}) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	if _, err := ParseNetworkSettings("httpupgrade", json.RawMessage(`{"host":1}`)); err == nil {
		t.Error("a numeric host was accepted")
	}
}

func TestParseNetworkSettingsGRPC(t *testing.T) {
	settings := parseNetwork(t, "grpc", `{"serviceName":"fixture-service"}`)
	if settings.ServiceName != "fixture-service" || settings.Path != "" {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	settings = parseNetwork(t, "grpc", `{"path":"/x","network":"x","serviceName":null}`)
	if settings.ServiceName != "" || settings.Path != "" || !reflect.DeepEqual(settings.UnknownKeys, []string{"network", "path"}) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	if _, err := ParseNetworkSettings("grpc", json.RawMessage(`{"serviceName":1}`)); err == nil {
		t.Error("a numeric serviceName was accepted")
	}
}

func TestParseNetworkSettingsXHTTP(t *testing.T) {
	settings := parseNetwork(t, "xhttp", `{"path":"/xh","host":"cover.example","mode":"stream-one","extra":{"noGRPCHeader":true,"noSSEHeader":true,"scMaxBufferedPosts":7,"scMaxEachPostBytes":"1000000-2000000","scStreamUpServerSecs":"20-80","xPaddingBytes":"100-1000","downloadSettings":{"port":8443}}}`)
	want := XHTTPSettings{
		Mode:             "stream-one",
		NoGRPCHeader:     true,
		NoSSEHeader:      true,
		MaxPostBytes:     XHTTPRange{Min: 1000000, Max: 2000000},
		MaxBufferedPosts: 7,
		StreamUpSeconds:  XHTTPRange{Min: 20, Max: 80},
		PaddingBytes:     XHTTPRange{Min: 100, Max: 1000},
		DownloadPort:     8443,
	}
	if settings.Path != "/xh" || settings.Host != "cover.example" || !reflect.DeepEqual(settings.XHTTP, want) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	if len(settings.UnknownKeys) != 0 {
		t.Fatalf("unexpected unknown keys: %v", settings.UnknownKeys)
	}
	settings = parseNetwork(t, "xhttp", `{"path":"","mode":"","host":null}`)
	if settings.Path != "/" || !reflect.DeepEqual(settings.XHTTP, DefaultXHTTPSettings()) {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	settings = parseNetwork(t, "xhttp", `{"private-extra":1,"extra":{"unknownKey":2,"downloadSettings":{"address":"x"}}}`)
	wantUnknown := []string{"extra.downloadSettings.address", "extra.unknownKey", "private-extra"}
	if !reflect.DeepEqual(settings.UnknownKeys, wantUnknown) {
		t.Fatalf("unknown keys = %v, want %v", settings.UnknownKeys, wantUnknown)
	}
}

func TestParseNetworkSettingsXHTTPRanges(t *testing.T) {
	for _, test := range []struct {
		raw   string
		field string
		want  XHTTPRange
	}{
		{`"scMaxEachPostBytes":1000000`, "maxPostBytes", XHTTPRange{Min: 1000000, Max: 1000000}},
		{`"scMaxEachPostBytes":"4096"`, "maxPostBytes", XHTTPRange{Min: 4096, Max: 4096}},
		{`"scMaxEachPostBytes":"3-4"`, "maxPostBytes", XHTTPRange{Min: 3, Max: 4}},
		{`"scMaxEachPostBytes":"-1"`, "maxPostBytes", XHTTPRange{Min: -1, Max: -1}},
		{`"scStreamUpServerSecs":"20-80"`, "streamUpSeconds", XHTTPRange{Min: 20, Max: 80}},
		{`"xPaddingBytes":"100-1000"`, "paddingBytes", XHTTPRange{Min: 100, Max: 1000}},
	} {
		settings := parseNetwork(t, "xhttp", `{"extra":{`+test.raw+`}}`)
		got := settings.XHTTP.MaxPostBytes
		switch test.field {
		case "streamUpSeconds":
			got = settings.XHTTP.StreamUpSeconds
		case "paddingBytes":
			got = settings.XHTTP.PaddingBytes
		}
		if got != test.want {
			t.Errorf("%s = %+v, want %+v", test.raw, got, test.want)
		}
	}
	for _, raw := range []string{
		`"scMaxEachPostBytes":"1-2-3"`,
		`"scMaxEachPostBytes":"a"`,
		`"scMaxEachPostBytes":{}`,
		`"scMaxEachPostBytes":[1]`,
		`"scMaxEachPostBytes":true`,
		`"scMaxBufferedPosts":"x"`,
		`"noGRPCHeader":"yes"`,
		`"noSSEHeader":1`,
		`"downloadSettings":{"port":0}`,
		`"downloadSettings":{"port":70000}`,
		`"downloadSettings":1`,
	} {
		if _, err := ParseNetworkSettings("xhttp", json.RawMessage(`{"extra":{`+raw+`}}`)); err == nil {
			t.Errorf("extra %s accepted", raw)
		}
	}
}

func TestParseNetworkSettingsXHTTPNulls(t *testing.T) {
	settings := parseNetwork(t, "xhttp", `{"path":null,"host":null,"mode":null,"extra":null}`)
	if settings.Path != "/" || settings.Host != "" || !reflect.DeepEqual(settings.XHTTP, DefaultXHTTPSettings()) {
		t.Fatalf("nulls changed defaults: %+v", settings)
	}
	settings = parseNetwork(t, "xhttp", `{"extra":{"noGRPCHeader":null,"scMaxEachPostBytes":null,"xPaddingBytes":null,"downloadSettings":null}}`)
	if !reflect.DeepEqual(settings.XHTTP, DefaultXHTTPSettings()) {
		t.Fatalf("null extra fields changed defaults: %+v", settings.XHTTP)
	}
}

func TestParseNetworkSettingsTCPHeader(t *testing.T) {
	settings := parseNetwork(t, "tcp", `{"header":{"type":"http","request":{"version":"1.1","method":"GET","path":["/a","/b"],"headers":{"Host":["a.example","b.example"],"User-Agent":"fixture"}},"response":{"version":"1.1","status":"200","reason":"OK","headers":{"X-Extra":"v","Content-Type":["text/html"]}}}}`)
	header := settings.TCPHeader
	if header == nil {
		t.Fatal("no header decoded")
	}
	if header.Type != "http" || header.RequestVersion != "1.1" ||
		!reflect.DeepEqual(header.RequestPaths, []string{"/a", "/b"}) ||
		!reflect.DeepEqual(header.RequestHosts, []string{"a.example", "b.example"}) {
		t.Fatalf("unexpected request: %+v", header)
	}
	if header.ResponseVersion != "1.1" || header.ResponseStatus != "200" || header.ResponseReason != "OK" {
		t.Fatalf("unexpected response: %+v", header)
	}
	wantHeaders := []HeaderField{
		{Name: "Content-Type", Values: []string{"text/html"}},
		{Name: "X-Extra", Values: []string{"v"}},
	}
	if !reflect.DeepEqual(header.ResponseHeaders, wantHeaders) {
		t.Fatalf("response headers = %+v, want %+v", header.ResponseHeaders, wantHeaders)
	}
	if !reflect.DeepEqual(settings.UnknownKeys, []string{"header.request.headers.User-Agent"}) {
		t.Fatalf("unknown keys = %v", settings.UnknownKeys)
	}
	settings = parseNetwork(t, "tcp", `{"header":{"type":"http","request":{"path":"/only"}}}`)
	if settings.TCPHeader == nil || !reflect.DeepEqual(settings.TCPHeader.RequestPaths, []string{"/only"}) {
		t.Fatalf("unexpected single path: %+v", settings.TCPHeader)
	}
}

func TestParseNetworkSettingsTCPHeaderAbsent(t *testing.T) {
	for _, raw := range []string{`{}`, `{"header":[]}`, `{"header":null}`, `{"header":{}}`, `{"header":{"type":"none"}}`, `{"header":{"type":null}}`} {
		settings := parseNetwork(t, "tcp", raw)
		if settings.TCPHeader != nil {
			t.Errorf("%s decoded %+v", raw, settings.TCPHeader)
		}
	}
	settings := parseNetwork(t, "tcp", `{"header":{"type":"http","request":null,"response":null}}`)
	if settings.TCPHeader == nil || settings.TCPHeader.Type != "http" || len(settings.UnknownKeys) != 0 {
		t.Fatalf("unexpected header: %+v", settings)
	}
}

func TestParseNetworkSettingsTCPHeaderUnknown(t *testing.T) {
	settings := parseNetwork(t, "tcp", `{"private-extra":1,"header":{"type":"none","private-header":2}}`)
	want := []string{"header.private-header", "private-extra"}
	if !reflect.DeepEqual(settings.UnknownKeys, want) {
		t.Fatalf("unknown keys = %v, want %v", settings.UnknownKeys, want)
	}
	settings = parseNetwork(t, "tcp", `{"header":{"type":"http","request":{"private-request":1,"headers":[]},"response":{"private-response":1,"headers":[]}}}`)
	want = []string{"header.request.private-request", "header.response.private-response"}
	if !reflect.DeepEqual(settings.UnknownKeys, want) {
		t.Fatalf("unknown keys = %v, want %v", settings.UnknownKeys, want)
	}
}

func TestParseNetworkSettingsTCPHeaderErrors(t *testing.T) {
	for _, raw := range []string{
		`{"header":"x"}`,
		`{"header":[1]}`,
		`{"header":{"type":"splithttp"}}`,
		`{"header":{"type":1}}`,
		`{"header":{"type":"http","request":3}}`,
		`{"header":{"type":"http","request":{"path":3}}}`,
		`{"header":{"type":"http","request":{"headers":{"Host":3}}}}`,
		`{"header":{"type":"http","response":{"status":{}}}}`,
		`{"header":{"type":"http","response":{"headers":{"X":3}}}}`,
	} {
		if _, err := ParseNetworkSettings("tcp", json.RawMessage(raw)); err == nil {
			t.Errorf("tcp %s accepted", raw)
		}
	}
}
