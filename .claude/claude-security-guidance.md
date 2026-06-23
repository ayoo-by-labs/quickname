# Security guidance — quickname

Codebase-specific security policy for the **quickname** Cloudflare Worker. This file is
committed on purpose: it tells reviewers and agents the trust boundaries and the rules that
protect them. British spelling throughout.

## What this is
A single-file, **service-worker-format** Cloudflare Worker (`index.js`) that:
- serves two inline HTML documents (the shortener form, the 404) under a strict nonce CSP;
- accepts `POST /` with a JSON body (`origin`, `alias`, `totp`) to create a short link;
- stores `alias → URL` in a KV namespace (`KV_STORE`) and `301`-redirects `GET /<alias>`;
- gates permanent (non-expiring) links behind a **TOTP** check (`TOTP_SECRET`, an env secret).

The trust boundary is the `POST /` body and the request path. Everything in the body is
attacker-controlled.

## Non-negotiable rules

### Content Security Policy (the headline control)
- **Never weaken `default-src 'none'`.** Add the narrowest directive needed, nothing broader.
- **Never add `'unsafe-eval'`**, and never add `'unsafe-inline'` to `script-src` without a nonce
  beside it. Every inline `<style>`/`<script>` and every nonced `<link>` MUST carry its
  per-request nonce (`imageNonce`/`manifestNonce`/`scriptNonce`/`styleNonce`).
- Nonces are generated per request in `nonceGenerator()` from `crypto.getRandomValues`. Do not
  make them static, reuse them across responses, or shrink the entropy.
- Only add an external origin to the CSP if a resource genuinely needs it. When a dependency is
  removed, remove its origin too (e.g. dropping Bootstrap ⇒ drop `cdn.jsdelivr.net`).
- Keep the security headers: `strict-transport-security`, `x-frame-options: DENY`,
  `x-content-type-options: nosniff`, `referrer: strict-origin`.

### Redirect / SSRF / open-redirect
- Stored redirect targets MUST pass `verifyUrl()` — **http/https only**. Never store or
  `Response.redirect()` to `javascript:`, `data:`, `vbscript:`, or scheme-relative junk.
- `verifyUrl()`'s regex deliberately rejects private/loopback/link-local IP ranges; do not relax
  it. A shortener that resolves to internal addresses is an SSRF/redirect-laundering vector.
- The self-redirect guard (reject `http(s)://quickna.me…`) stays — it stops redirect loops/abuse.

### Injection / XSS
- `alias` is constrained to `^[a-z0-9\-]+$` and lower-cased before use. Keep that regex; it is
  what makes the alias safe to interpolate into the success-response HTML (`#redirLink` href) and
  into KV keys/paths. Any new reflection of user input into HTML must be either regex-constrained
  like this or HTML-escaped.
- Do **not** interpolate the raw `origin` URL into HTML. It is only stored and redirected to.
- Reserved aliases (`awnvbg`, `c2VydmljZS13b3JrZXI`, `qnmesh`) must stay rejected on create.

### Secrets & auth
- `TOTP_SECRET` is an env secret (wrangler `secrets:` / `wrangler secret put`). Never hard-code
  it, never echo it into a response, log, or error body. The `typeof TOTP_SECRET !== 'undefined'`
  guard must keep the worker functional when the secret is absent (links just expire in 7 days).
- The TOTP path is the only authorisation in the app; keep the "no TOTP ⇒ 7-day TTL" behaviour so
  an unauthenticated user can never mint a permanent link.

### Input handling
- Treat the `POST /` JSON as hostile: it may be missing fields, wrong types, or huge. Validate
  before use (the existing alias/URL/TOTP checks). Do not add `eval`/`Function`/dynamic `import`
  on any request-derived value.

## Out of scope (acknowledged, not regressions)
- No per-IP rate limiting on `POST /` or on TOTP attempts (6-digit/30s TOTP + Cloudflare in front
  is the current posture). The TOTP comparison is not constant-time — acceptable for a 30-second
  6-digit window, but do not widen the window or add hints that enable enumeration.
- `Math.random()` is used for alias/title selection (non-security); nonces use `crypto`. Keep that
  split — never move nonce/secret generation onto `Math.random()`.
