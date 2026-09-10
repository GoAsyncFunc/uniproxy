# Contract and integration validation

## Offline tests (no panel credentials)

```sh
go test ./... -race -cover -count=1
go test ./pkg -run 'TestPanelFixtureHTTPTransitions|TestClientTLSCertificateValidation' -race -count=10
```

`TestPanelFixtureHTTPTransitions` runs all protocol fixtures through the full
HTTP client: VMess, VLESS, Trojan, Shadowsocks, Hysteria v1/v2, TUIC and AnyTLS.
It asserts endpoint/auth query construction and the sequence:

1. Valid full response, including protocol-specific field assertions.
2. 304 with a replacement ETag.
3. Invalid full response: parse error without committing hash or ETag.
4. 304: previous validator remains usable.
5. Valid changed config: new server port, hash and ETag are accepted.
6. 304 for the updated config.

Fixtures include synthetic payloads and sanitized VLESS panel samples. This
checks compatibility with those samples, not every possible configuration or
live support for all protocols.

`TestClientTLSCertificateValidation` checks that an untrusted local TLS server
is rejected with one connection attempt and no HTTP request. A separate test
trusts only the test certificate and confirms successful HTTP operation without
disabling certificate validation. Existing tests cover redirect rejection,
IPv4/IPv6 loopback, local address binding and idle-connection cleanup. They do
not simulate public-network dual-stack blackholes or every TLS failure.

## Live validation safety and remaining scope

There is no automatically enabled live test or credential in this repository.
`TestIntegrationPanelFetch` is skipped unless explicitly enabled. It fetches
config/users twice and alive counts once, but creates no records and sends no
POST requests. Repeat reads do not require 304, since data may change during a
run. It checks fetch contracts, not real proxy connectivity or exact accounting.

Create a private JSON file **outside the repository** with these fields:

```json
{"APIHost":"https://test-panel.example.com","Key":"REPLACE_LOCALLY","NodeType":"vless","NodeID":1}
```

On Unix, set mode 600. On Windows, restrict the file ACL to the current account;
the test cannot validate Windows ACLs. Then run explicitly (never use a production
node without understanding the GET cache side effects):

```sh
chmod 600 /secure/path/panel.json
UNIPROXY_INTEGRATION=1 UNIPROXY_INTEGRATION_CONFIG=/secure/path/panel.json \
  go test ./pkg -run '^TestIntegrationPanelFetch$' -count=1 -v
```

Only the file path is passed through the environment; tokens must not be placed
in command arguments or committed examples. Errors deliberately omit panel
payloads and configuration details. Library-internal sanitized logging may still
occur. The test adds no flag for traffic/online mutation: those checks require a
separate, reviewed fixture lifecycle to avoid unsafe replays or orphan records.

CI runs normal tests on Linux, macOS and Windows using the toolchain in go.mod;
Linux additionally runs race and coverage checks. No live panel secrets are
configured in CI. IPv6 tests skip explicitly when IPv6 loopback is unavailable.

Before any live run:

- Verify the effective database/cache configuration, not just `.env`.
- Record the deployed controller revision and local modifications.
- Use dedicated users and hidden nodes, with reminders disabled and reserved
  example hostnames/addresses. Do not modify existing customer records.
- Keep credentials local with restrictive file permissions. Never put tokens in
  command arguments, fixtures, test output or repository files.
- Remember that even user/alive GET endpoints can update panel cache state.
- Send traffic increments only once; a lost acknowledgement is not permission to
  replay. Verify asynchronous accounting and statistics separately.
- Record created IDs, clean up only those records/cache fields, and restore any
  temporary configuration. Do not flush shared Redis databases or queues.

The manual development-panel run before v0.1.2 verified VLESS, Hysteria v1/v2,
user updates, online IP normalization/clearing, and one incremental traffic
report. It did not validate real proxy connections or all protocols. Remaining
live targets include VMess, Trojan, Shadowsocks, TUIC, AnyTLS, HTTPS/proxy paths,
and actual network-failure recovery. Offline tests must not be reported as
substitutes for these live checks.
