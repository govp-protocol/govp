# Public protocol scope

This repository contains the material required to implement and verify the
open GOVP protocol family:

- the frozen GOVP-1 core specification;
- governed open extensions registered by the project;
- normative specifications, machine-readable schemas and conformance vectors;
- minimal reference issuing, verification and command-line components;
- synthetic examples, tests and release tooling.

An open extension is part of this repository only when its public contract is
reviewable and independently implementable. That contract includes its schema,
conformance vectors, receiver and rejection behaviour, and threat model, as
required by the extension registry. Registration proves protocol compatibility;
it does not certify that an external claim is true or sufficient for a
regulated purpose.

It intentionally excludes issuing products, user and tenant management,
control panels, hosted services, orchestration, observers, operational data,
customer integrations, private keys, proprietary policy packs, regulated
enforcement and commercial extensions. Those systems are neither disclosed nor
required to implement the open protocol family.

Conformance claims are scoped. GOVP-1 conformance does not imply conformance
with an extension, and extension conformance does not imply certification or
regulatory sufficiency. Compatibility claims are technical claims. They do not
imply endorsement or permission to use project trademarks beyond accurate
descriptive reference.
