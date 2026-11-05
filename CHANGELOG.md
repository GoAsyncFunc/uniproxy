# Changelog

## v0.1.6

- Add WS `NetworkSettings.MaxEarlyData` and `EarlyDataHeaderName`, decoding
  the panel's `maxEarlyData` and `earlyDataHeaderName` for every protocol using
  that transport. An absent/null maximum is nil; explicit zero is preserved.
- Reject wrong JSON types with static diagnostics; keep path/Host behavior
  and unknown-key reporting unchanged. Bounds, defaults, header policy and
  path normalization remain node decisions. No dependencies changed.

Compatibility: no exported symbol was removed or function signature changed.
Adding struct fields can break unkeyed literals; use keyed literals. The two
WS keys are now modeled instead of being reported in `UnknownKeys`.

## v0.1.5

Changes since v0.1.4:

- Decode the shapes panel editors emit for settings: untouched settings arrive
  as an empty array, numbers may arrive as strings, and header values may arrive
  as a string or as a list. `TlsSettings` and `EncSettings` now normalize those
  shapes in `UnmarshalJSON`; an unset field stays unset instead of failing the
  decode, and a field of the wrong JSON type is still an error.
- Add `TlsSettings.PublicKey`, `TlsSettings.Ech`, `TlsSettings.EchConfig` and
  `EncSettings.Rtt`, which were previously dropped while decoding.
- Add `ParseNetworkSettings` and the typed `NetworkSettings`, `XHTTPSettings`,
  `XHTTPRange`, `TCPHeader` and `HeaderField` values for the tcp, ws,
  httpupgrade, grpc and xhttp settings every node backend parses. Unknown keys
  are reported as dotted paths rather than rejected.
- Add the REALITY helpers `TlsSettings.DecodePrivateKey`, `DecodePublicKey`,
  `DecodeShortID`, `Destination` and `DecodeMLDSA65Seed`, and
  `EncSettings.DecodeKey` returning an `EncKeyKind`.
- These helpers normalize and report only. Whether a value is acceptable for a
  node, and what the node does with an unknown key, remains a node decision; the
  README states that boundary.

Compatibility: `TlsSettings` and `EncSettings` now define `UnmarshalJSON`, and
`TlsSettings` gained a `[]string` field, so neither value is comparable with
`==` and unkeyed struct literals in downstream code can break; use keyed
literals. The API additions are additive and no exported symbol was removed. A
scalar field the panel writes as `null` now means unset rather than an error,
matching the existing handling of `[]`; a node-side parser that rejected `null`
can therefore become more tolerant when it adopts `ParseNetworkSettings`.

Dependencies: the patched development toolchain moves to Go 1.27.3, and the
indirect `golang.org/x/net` and `golang.org/x/sys` requirements move to v0.58.0
and v0.47.0. The module language minimum remains Go 1.25, and downstream
applications should build with a supported, security-patched Go release.

## v0.1.4

- Add an explicitly enabled, GET-only panel integration test and macOS/Windows
  CI alongside the existing Linux race, coverage and security checks.
- Harden the opt-in integration runner with bounded configuration reads,
  opened-file permission checks and fixed error summaries; add offline safety
  tests for GET-only behavior, credential protection and request cancellation.
- Return a construction error when the global default transport is nil or not
  `*http.Transport`, instead of panicking. The legacy `New` wrapper returns nil.
- Use one validation/construction path for both constructors.
- Add real HTTP observer regressions for cancellation, deadlines, response-size
  limits, invalid JSON, unsolicited 304 and negative online acknowledgements.

## v0.1.3

Changes since v0.1.2:

- Add optional `Config.Observer`, `RequestObserver`, `RequestEvent` and
  `RequestOutcome` for per-HTTP-attempt metadata without credentials, payloads or
  raw errors. The callback is synchronous, concurrent-safe on the caller's side,
  non-reentrant, and panic-isolated. HTTP outcomes are not logical API success.
- Skip impossible error-redaction regexp scans using necessary delimiters,
  preserving the prior replacement order and Unicode matching behavior.
- Add differential redaction fuzz coverage, full HTTP fixture transitions for all
  supported protocols, and TLS trust/certificate-error retry tests.
- Document performance limitations and SDK contract testing requirements.

No automatic POST retries or new runtime dependencies are introduced. No public
API symbols were removed. Adding `Observer` to the exported `Config` struct can
break external unkeyed struct literals; use keyed literals as in the README.
The patched development toolchain remains Go 1.26.8 and the module's Go language
minimum remains 1.25. Downstream applications should use a supported patched Go.

## v0.1.2

- Harden panel response contracts, report acknowledgements, cache validators,
  duration boundaries, protocol versions and online payload validation.
- Support numeric/string xver, per-user online clearing and IP normalization.
- Use native dual-stack dialing and expose idle connection cleanup.
- Update patched toolchain/dependencies and optimize UUID format validation.
