# GOVP visual identity

This directory is the canonical, editable source for the public GOVP visual
identity. GOVP is presented as an independent open protocol stewarded by
Gemacode, a brand of Brilyetz Holding S.L.

The mark is an open `G` drawn as one continuous path between two nodes. It
represents the protocol relationship between a signed record and the exact
artifact bytes that a recipient verifies. It deliberately avoids locks,
shields, blockchains, fingerprints and certification imagery: GOVP verifies
cryptographic integrity; it does not certify truth or institutional identity.

## Asset inventory

| File | Intended use |
|---|---|
| `govp-mark.svg` | Primary transparent mark on light or dark neutral surfaces |
| `govp-mark-monochrome.svg` | Single-colour printing or contexts that cannot reproduce the palette |
| `govp-avatar.svg` / `.png` | GitHub organization avatar and square application surfaces |
| `govp-favicon.svg` | Browser and small icon surfaces |
| `govp-wordmark-light.svg` / `.png` | Wordmark for light backgrounds |
| `govp-wordmark-dark.svg` / `.png` | Wordmark for dark backgrounds |
| `govp-org-header.svg` / `.png` | GitHub organization profile header |
| `govp-social-preview.svg` / `.png` | Repository and link preview at 1280 × 640 |
| `govp-flow.svg` / `.png` | Explanatory “Sign → Distribute → Verify” diagram |

SVG files are the editable masters. PNG files are deterministic renders for
services that do not accept SVG. [`ASSET-MANIFEST.json`](ASSET-MANIFEST.json)
records their dimensions, renderer and SHA-256 hashes for independent audit.

## Palette

| Token | Hex | Use |
|---|---|---|
| Midnight | `#07182C` | Primary dark ground and institutional anchor |
| Electric blue | `#3E7BFA` | Protocol path and primary action |
| Bright blue | `#5C8DFF` | Protocol path on dark surfaces |
| Cyan | `#22C7E5` | Verification nodes and restrained highlights |
| Cloud | `#F6F8FC` | Light ground and text on midnight |
| Slate | `#607086` | Supporting copy on light surfaces |

## Usage rules

- Preserve the mark proportions, colours and continuous-path geometry.
- Keep clear space around the mark equal to at least one cyan node diameter.
- Use the favicon below 48 px; do not add taglines at small sizes.
- Use the monochrome asset only when the primary palette is unavailable.
- Do not add a checkmark, lock, shield or “certified” treatment.
- Do not use the mark to imply endorsement, certification or affiliation.
- Pair the official identity with the wording “Open protocol stewarded by
  Gemacode” when project stewardship needs to be stated.

## Rights

Copyright © 2026 Brilyetz Holding S.L. All rights reserved.

The GOVP name and visual marks are associated with Brilyetz Holding S.L. and
its Gemacode brand. The files in this directory are not included in the
repository's Apache-2.0 grant. They are provided for accurate identification
of the project and truthful compatibility references, subject to
[`../TRADEMARKS.md`](../TRADEMARKS.md). No trademark licence or right to imply
endorsement is granted.
