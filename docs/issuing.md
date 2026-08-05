# Issuing GOVP records

Verification remains the safest integration boundary. GOVP 0.1.10 also exposes
an issuance path so adopters do not need to reconstruct the signing algorithm.

## Local CLI example

Create an Ed25519 PKCS8 key for development or low-volume local issuance:

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out issuer-private.pem
chmod 600 issuer-private.pem
```

Keep that file outside the repository and web root. Issue a record for exact
asset bytes:

```bash
govp issue \
  --asset release.txt \
  --canonical 'https://issuer.example/.well-known/govp/{govp-id}.govp' \
  --publisher "Example issuer" \
  --asset-type document \
  --asset-id example/release-1 \
  --evidence https://issuer.example/releases/release.txt \
  --license Apache-2.0 \
  --private-key issuer-private.pem \
  --output release.govp
```

The CLI computes the asset digest, GOVP-ID, raw public key and Ed25519
signature. It refuses broad POSIX key permissions and refuses to overwrite an
existing output file. It never generates, prints or uploads a private key.
The literal `{govp-id}` in `--canonical` is replaced before signing.

The URL passed as `--canonical` must be the exact final HTTPS URL from which
this record will be fetched. Use `/.well-known/govp.txt` only for the domain
identity record itself.

## Python API

```python
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from govp import serialize_record, sign_record

private_key = serialization.load_pem_private_key(
    Path("issuer-private.pem").read_bytes(), password=None
)
fields = {
    "canonical": "https://issuer.example/.well-known/govp/record.govp",
    "publisher": "Example issuer",
    "asset-type": "document",
    "asset-id": "example/release-1",
    "asset-sha256": "<lowercase SHA-256 of exact asset bytes>",
    "evidence": "https://issuer.example/releases/release.txt",
    "profile": "GOVP-BASIC",
    "generated-at": "2026-08-05T00:00:00Z",
}
record = sign_record(fields, private_key)
Path("release.govp").write_text(serialize_record(record), encoding="utf-8")
```

`sign_record` accepts an `Ed25519PrivateKey`, so KMS/HSM integrations can keep
key loading and custody outside GOVP. The caller is responsible for the truth
of declarations and publication policy.

## Production controls

- use a dedicated signer and least privilege;
- require review for canonical, publisher, asset identity and evidence URL;
- verify the emitted record and exact asset before publication;
- publish and monitor GOVP-STATUS-1;
- retain immutable release hashes and an issuance audit trail;
- use an independent timestamp or transparency service when time matters.
