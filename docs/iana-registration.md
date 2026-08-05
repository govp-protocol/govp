# IANA Well-Known URI registration request

This is the public review draft for two provisional registrations under RFC
8615. Submit to `wellknown-uri-review@ietf.org` after the published URLs and
media types have passed release validation.

## Registration 1

- URI suffix: `govp.txt`
- Change controller: Gemacode (Brilyetz Holding S.L.),
  `research@gemacode.org`, `https://govp.io`
- Specification document: `https://govp.io/govp/spec/govp-1.html`, sections 4,
  10.3, 11 and 12
- Status: provisional
- Related information: `https://govp.io/govp/security.html`

`/.well-known/govp.txt` is the line-oriented GOVP-1 identity record for an HTTPS
origin. It is served as `text/plain; charset=utf-8`. GOVP-1 defines exact
parsing, canonical URL binding, signatures, identifiers, resource limits and
security considerations.

## Registration 2

- URI suffix: `govp`
- Change controller: Gemacode (Brilyetz Holding S.L.),
  `research@gemacode.org`, `https://govp.io`
- Specification documents: `https://govp.io/govp/spec/govp-1.html`, section 11,
  and `https://github.com/govp-protocol/govp/blob/main/extensions/status-1/GOVP-STATUS-1.md`
- Status: provisional
- Related information: `https://govp.io/govp/docs.html`

The suffix is the root for GOVP discovery and status resources:

- `/.well-known/govp/index.json` — `application/json` discovery index;
- `/.well-known/govp/revoked.json` — `application/json` GOVP-STATUS-1;
- `/.well-known/govp/<GOVP-ID>.govp` — `text/plain; charset=utf-8` record.

Only HTTPS is used. Read endpoints are public and normally permit cross-origin
reads. GOVP records contain public keys, signatures and public evidence links;
operators must not publish private or personal material unintentionally.
Clients reject credentialed URLs and downgrade redirects, impose resource
limits, treat linked evidence as untrusted and separate core validity from
online status and application trust.
