package pkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzNodeHandlersParseConfig(f *testing.F) {
	for _, fixture := range loadFuzzFixtures(f) {
		if fixture.Protocol == "common" {
			continue
		}
		f.Add(fixture.Protocol, string(fixture.Body))
	}

	f.Fuzz(func(t *testing.T, protocol string, body string) {
		handler := fuzzHandlerForProtocol(protocol)
		if handler == nil {
			return
		}

		info := &NodeInfo{Id: 1, Type: protocol}
		common, err := handler.ParseConfig(info, []byte(body))
		if err != nil || common == nil {
			return
		}
		_ = validateCommonNode(common)
		_ = validateProtocolSpecificNode(info)
		info.ProcessCommonNode(common)
	})
}

func FuzzNormalizeRouteMatch(f *testing.F) {
	for _, seed := range []string{
		"example.com, regexp:.*ads.* , protocol:bittorrent",
		"",
		"   ",
		"one,, two , ,three",
		"[\"domain:example.com\",\"geosite:cn\"]",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body string) {
		assertTrimmedMatches(t, NormalizeRouteMatch(body))

		var decoded []interface{}
		if err := json.Unmarshal([]byte(body), &decoded); err == nil {
			assertTrimmedMatches(t, NormalizeRouteMatch(decoded))
		}
	})
}

func FuzzDNSMatches(f *testing.F) {
	for _, seed := range []string{
		"main,{\"servers\":[\"1.1.1.1\",\"8.8.8.8\"]}",
		"main,{bad-json",
		"domain:example.com,geosite:cn",
		"",
	} {
		f.Add(seed, "1.1.1.1")
	}

	f.Fuzz(func(t *testing.T, match string, actionValue string) {
		route := Route{Action: RouteActionDNS, Match: match, ActionValue: actionValue}
		matches := route.DNSMatches()
		if strings.HasPrefix(strings.TrimSpace(match), "main,") && len(matches) > 0 && matches[0] != "main" {
			t.Fatalf("main DNS match prefix = %q", matches[0])
		}
		_ = validateDNSRoute(route)
	})
}

func FuzzValidateCommonNode(f *testing.F) {
	for _, fixture := range loadFuzzFixtures(f) {
		if fixture.Protocol == "common" {
			f.Add(string(fixture.Body))
			continue
		}
		handler := fuzzHandlerForProtocol(fixture.Protocol)
		if handler == nil {
			continue
		}
		info := &NodeInfo{Id: 1, Type: fixture.Protocol}
		common, err := handler.ParseConfig(info, fixture.Body)
		if err != nil || common == nil {
			continue
		}
		body, err := json.Marshal(common)
		if err == nil {
			f.Add(string(body))
		}
	}
	f.Add(`{"server_port":443}`)
	f.Add(`{"server_port":0}`)
	f.Add(`{"server_port":65536}`)

	f.Fuzz(func(t *testing.T, body string) {
		var common CommonNode
		if err := json.Unmarshal([]byte(body), &common); err != nil {
			return
		}
		_ = validateCommonNode(&common)
		info := &NodeInfo{Id: 1, Type: "fuzz"}
		info.ProcessCommonNode(&common)
	})
}

func assertTrimmedMatches(t *testing.T, matches []string) {
	t.Helper()

	for _, match := range matches {
		if match == "" {
			t.Fatal("empty match returned")
		}
		if match != strings.TrimSpace(match) {
			t.Fatalf("match not trimmed: %q", match)
		}
	}
}

type fuzzFixture struct {
	Protocol string
	Body     []byte
}

func loadFuzzFixtures(tb testing.TB) []fuzzFixture {
	tb.Helper()

	var fixtures []fuzzFixture
	roots := []string{
		filepath.Join("testdata", "panels", "synthetic"),
		filepath.Join("testdata", "panels", "real"),
	}
	for _, root := range roots {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fixtures = append(fixtures, fuzzFixture{
				Protocol: fuzzProtocolFromFixturePath(path),
				Body:     body,
			})
			return nil
		})
		if err != nil {
			tb.Fatalf("walk fuzz fixtures under %s: %v", root, err)
		}
	}
	return fixtures
}

func fuzzProtocolFromFixturePath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		if part == "synthetic" && i+1 < len(parts) {
			return parts[i+1]
		}
		if part == "real" && i+2 < len(parts) {
			return parts[i+2]
		}
	}
	return ""
}

func fuzzHandlerForProtocol(protocol string) NodeHandler {
	switch protocol {
	case Vmess:
		return &VMessHandler{}
	case Vless:
		return &VlessHandler{}
	case Shadowsocks:
		return &ShadowsocksHandler{}
	case Trojan:
		return &TrojanHandler{}
	case Tuic:
		return &TuicHandler{}
	case Hysteria:
		return &HysteriaHandler{}
	case Hysteria2:
		return &Hysteria2Handler{}
	case AnyTls:
		return &AnyTlsHandler{}
	default:
		return nil
	}
}
