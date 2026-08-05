# Integration guide

GOVP is designed so consumers can verify records without trusting a central
service. Integrations should preserve that property and keep transport,
cryptographic verification and business policy as separate decisions.

## Recommended flow

1. Obtain the UTF-8 GOVP record from a local file or an HTTPS response.
2. Parse it without rendering comments or field values as markup.
3. Verify all core checks.
4. When available, supply the asset bytes and require the asset check.
5. When fetched remotely, supply the final response URL and require canonical
   binding.
6. Apply local policy to advisory warnings and evidence URL schemes.
7. Store the original record, result and asset digest for auditability.

## Composed evidence workflow

The asset bound by `asset-sha256` is an opaque byte sequence. It can therefore
be a SCITT statement or receipt, a COSE message, a DSSE envelope, an in-toto
attestation or a Sigstore bundle. GOVP verifies the exact bytes; it does not
interpret the upstream object's internal trust semantics.

For composed evidence:

1. Obtain the upstream evidence object and preserve its exact serialization.
2. Supply those bytes as the GOVP asset and require `checks.asset` to pass.
3. Run the upstream system's native verifier against the same bytes.
4. Apply application policy to the combined results.
5. Report the GOVP and upstream verdicts separately so that neither can be
   mistaken for the other.

In pseudocode:

```text
govp_valid = verify_govp(record, upstream_bytes)
source_valid = verify_with_native_system(upstream_bytes)
accepted = govp_valid AND source_valid AND local_policy_allows(result)
```

A GOVP-valid result is not, by itself, a valid SCITT, COSE, DSSE, in-toto or
Sigstore result. See the [composition guide](composition.md) for system-specific
boundaries and primary references.

## Python API

```python
from pathlib import Path

from govp.core import load_record, verify

record = load_record(Path("record.govp.txt"))
asset = Path("asset.bin").read_bytes()
result = verify(record, asset_bytes=asset)

if not result.ok:
    raise ValueError(result.checks)

print(result.derived_govp_id)
print(result.warnings)
```

The Python module is the reference implementation, not a network trust
service. Applications remain responsible for download limits, persistence,
authorization and user-interface safety.

## Verification result

`Verification` contains:

- `ok`: conjunction of all applicable core checks;
- `fields`: parsed signed fields;
- `checks.format`: required fields and normative shapes;
- `checks.signature`: Ed25519 signature result;
- `checks.govp-id`: content-derived identifier result;
- `checks.canonical`: final URL binding, or `None` when offline;
- `checks.asset`: supplied asset digest result, or `None` when absent;
- `derived_govp_id` and `asset_sha256`;
- `warnings`: stable, non-fatal advisory identifiers.

Current warning identifiers are:

- `signed-non-printable-text`: signed free text contains a code point that
  should be escaped before display;
- `non-http-evidence-scheme`: the absolute evidence URI uses a scheme other
  than HTTP or HTTPS.

Warnings do not change core validity. A deployment may reject them as policy.

## URL handling

GOVP URL fields use visible ASCII RFC 3986 URI text. Use IDNA ASCII host names
and percent-encoded UTF-8 for internationalized components. Never place
credentials in a GOVP URL.

The signed evidence URI is untrusted input. Do not execute it, interpolate it
into HTML, follow non-HTTP schemes automatically or treat its content as safe
because the record is signed.

## Display handling

Comments are unsigned and must not be presented as verified. Field names and
free-text values are signed, but must still be escaped for HTML, terminals,
logs and structured output. Prefer JSON serialization to manual string
construction.

## Resource limits

The reference `verify-url` command caps remote records at 1 MiB and uses a
15-second request timeout. Services should also limit local uploads, asset
size, redirect count, concurrency and stored-result retention according to
their own threat model.

## Compatibility

Treat the conformance vectors, not incidental implementation behavior, as the
interoperability contract. Unknown fields remain signed and must be preserved.
Do not discard them before signature verification.
