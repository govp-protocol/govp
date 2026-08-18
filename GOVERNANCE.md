# Governance

GOVP is stewarded by Gemacode, a brand of Brilyetz Holding S.L. Stewardship
includes maintaining the normative specification, conformance corpus and
reference implementation while preserving vendor-neutral verification.

## Decision principles

Protocol decisions prioritize, in order:

1. deterministic interoperability;
2. security and explicit trust boundaries;
3. backward compatibility of published signing inputs;
4. implementability without a central service;
5. clear separation between the open protocol and optional products.

Material changes are proposed through issues and pull requests. Changes to the
frozen wire format require explicit versioning, conformance vectors and a
migration analysis. Reference-implementation changes require tests and must
not silently redefine protocol behavior.

Maintainers may reject contributions that include customer information,
credentials, private keys, proprietary application code or material outside
[`SCOPE.md`](SCOPE.md).

Apache-2.0 governs contributions. Trademark use remains subject to
[`TRADEMARKS.md`](TRADEMARKS.md); technical conformance does not imply
certification or endorsement.

Incoming code also follows [`IP_BOUNDARY.md`](IP_BOUNDARY.md). DCO sign-off is
mandatory provenance but is not sufficient evidence of assignment. Until the
governance model is deliberately changed, Brilyetz Holding S.L. verifies an
employment assignment or executed contributor/corporate IP agreement before
merging third-party code. This preserves a documented chain of title while the
project remains Apache-2.0 for every recipient.
