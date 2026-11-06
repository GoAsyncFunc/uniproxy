# Cross-Protocol Contracts

UniProxy and its consuming node backends are components of a multi-protocol
system. The goal is to share capabilities where they have the same semantics,
not to make distinct protocols look alike.

## Ownership

- The panel owns configured values and their source representation.
- UniProxy decodes and faithfully normalizes panel data. It preserves meaningful
  distinctions such as absent, null, empty and explicit zero, and reports
  unknown fields without deciding whether a node accepts them.
- Each node backend owns support policy, validation and protocol-specific
  adaptation to its data plane.

## When to define a shared contract

A public contract is appropriate when at least two concrete protocol consumers
use a capability with the same meaning. Document its field names and meaning,
units, ownership, lifecycle, absence/null/zero semantics, normalization,
compatibility policy and validation. Verify changes with UniProxy decoding
tests and tests in every affected backend. Avoid speculative abstractions without
concrete consumers.

## Keep wire protocols distinct

Shared internal capabilities can include dialing, generic stream/datagram
relays, traffic accounting, limits, device tracking, revocation and lifecycle
management when their semantics match. A protocol adapter remains responsible
for that protocol's authentication, commands, address representation, packet
boundaries and on-wire framing. Sharing a UDP relay does not imply that two
protocols use the same UDP encapsulation or multiplexing format.

## Compatibility boundary

An additive decoder field or shared contract still requires compatibility review
across UniProxy and the consuming backends. Do not change panel APIs or exported
SDK behavior solely to pursue generic architecture; follow the owning repository
constraints and obtain the required maintainer approval first. Fixtures prove
decoding behavior only, not live client interoperability or runtime support.
