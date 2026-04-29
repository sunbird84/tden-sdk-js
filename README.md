# @tden/sdk

> Status: **Phase A2.6** — OIDC client + scene-package read + webhook verifier shipping; full integration tests + Phase B JWKS-verified id_token to land next.

JavaScript SDK for "Sign in with TDEN" and TDEN scene-package management. Works in Node.js (server-side OAuth flow) and the browser (consent UI / passive-attribute reads).

## Install

```bash
npm install @tden/sdk
```

## Quick start (server-side OAuth code flow)

```ts
import { TDENClient } from '@tden/sdk'

const tden = new TDENClient({
  clientId: 'your_scene_package_id',          // from the TDEN portal
  clientSecret: process.env.TDEN_CLIENT_SECRET, // server-side only — NEVER bundle in browser
  redirectUri: 'https://your-app.example.com/auth/tden/callback',
})

// 1. Login route
app.get('/auth/tden/login', async (req, res) => {
  const { url, verifier, state, nonce } = await tden.authorizeURL({
    scope: 'openid your_scene_package_id',
  })
  req.session.tdenVerifier = verifier
  req.session.tdenState = state
  req.session.tdenNonce = nonce
  res.redirect(url)
})

// 2. Callback route
app.get('/auth/tden/callback', async (req, res) => {
  if (req.query.state !== req.session.tdenState) {
    return res.status(400).send('state mismatch')
  }
  const tokens = await tden.exchangeCode({
    code: req.query.code,
    verifier: req.session.tdenVerifier,
  })
  const user = await tden.userInfo(tokens.access_token)
  // user.did, user.is_real_name_verified, user.reputation_score, ...
  req.session.user = user
  res.redirect('/')
})
```

A complete runnable example lives in [`examples/express-server.mjs`](./examples/express-server.mjs).

## Scene-package read

```ts
import { ScenePackages } from '@tden/sdk'

const pkgs = new ScenePackages()
const list = await pkgs.listApproved()      // every approved package globally
const one = await pkgs.get('tden_demo_basic_v1')
```

## Webhook verifier

When users revoke / re-grant / expire consents, TDEN POSTs to your package's `webhook_url`. Verify the signature before mutating state:

```ts
import { verifyWebhook } from '@tden/sdk'

app.post('/webhooks/tden', express.raw({ type: 'application/json' }), async (req, res) => {
  const result = await verifyWebhook(
    req.body,                                  // raw bytes — NOT a parsed object
    req.headers['x-tden-signature'],
    process.env.TDEN_WEBHOOK_SECRET,
  )
  if (!result.ok) return res.status(401).send(result.error)
  // result.event = { event, grant_id, package_id, user_did, timestamp, reason }
  await yourBackend.applyConsentEvent(result.event)
  res.status(204).end()
})
```

> **Note:** Phase A2.4 of the gateway-side webhook delivery is still on roadmap. The SDK verifier is ready ahead of time so RPs can integrate with confidence.

## API surface stability

| API | Stability | Notes |
|---|---|---|
| `TDENClient.authorizeURL` | Stable | RFC 6749 + 7636 + OIDC core compliant |
| `TDENClient.exchangeCode` | Stable | Supports both PKCE-only public + `client_secret_post` confidential |
| `TDENClient.decodeIDToken` | Stable | **Does NOT verify signature** — Phase B adds verifyIDToken() with JWKS fetch |
| `TDENClient.userInfo` | Stable | GET /oauth/userinfo |
| `ScenePackages.*` | Stable | Read-only — public endpoints |
| `verifyWebhook` | Stable | HMAC-SHA256 with constant-time compare |

## Browser usage

The SDK is ESM + works in modern browsers. Use cases:

- Read scene-package list to render in your homepage's "Sign in with" UI
- Show pre-login attribute preview ("This site will see: real name, age range")
- Handle the consent UI integration

**Do NOT put `clientSecret` in browser code.** OAuth code-flow with `client_secret_post` is server-side only. For browser login, use the public-client variant (PKCE-only, no secret).

## Security

See [`tden-spec/spec/security-threat-model.md`](https://github.com/sunbird84/tden-spec/blob/master/spec/security-threat-model.md) §1.9.

## License

AGPL-3.0.
