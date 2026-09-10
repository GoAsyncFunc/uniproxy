# Changelog

## Unreleased

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
