# Publish GOVP evidence from CI

GOVP publication creates a static `.well-known/govp/` tree and a separate
custody directory. It does not deploy or operate a verification API.

First an administrator authorizes a developer key for exact event types:

```sh
govp publication authorize-key \
  --domain https://example.com \
  --domain-private-key domain.pem \
  --subordinate-public-key developer.pub.pem \
  --allow org.example.build/1 \
  --valid-from 2026-08-01T00:00:00Z \
  --valid-until 2026-09-01T00:00:00Z \
  --output developer-authorization.json
```

Commit a publish request that explicitly lists public types and marks every
event `publish` or `sealed_private`. In GitHub Actions, expose the domain key
from the protected environment and run:

```sh
govp publish --request publish-request.json \
  --domain-private-key "$GOVP_DOMAIN_KEY" \
  --public-dir site --custody-dir custody
```

Deploy only `site/`. Archive `custody/` under the organization's retention
policy. Deliver an individual `publication-proof-*.json` from custody when a
third party needs to verify an event.

From a clean machine, verify against a downloaded static tree:

```sh
govp publication verify proof.json --tree site
```

For a `sealed_private` bundle, verify entirely inside retained custody:

```sh
govp publication verify proof.json --custody custody
```

Or fetch only static files from an HTTPS domain:

```sh
govp publication verify proof.json --base-url https://example.com
```

For local hosting tests, loopback HTTP is accepted explicitly:

```sh
python -m http.server 8000 --directory site
govp publication verify proof.json --base-url http://127.0.0.1:8000
```

The result reports L0, L1 and L2 separately. A local tree can prove L1 but
cannot claim live L2.
