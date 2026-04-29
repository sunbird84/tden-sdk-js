// @tden/sdk — TDENClient: high-level OIDC client.
//
// 用法 / Usage(server-side Express 例子):
//
//   import { TDENClient } from '@tden/sdk'
//   const tden = new TDENClient({
//     clientId: 'tden_demo_basic_v1',
//     clientSecret: process.env.TDEN_CLIENT_SECRET!,   // never embed in browser
//     redirectUri: 'https://your-app.example.com/auth/tden/callback',
//   })
//
//   app.get('/auth/tden/login', async (req, res) => {
//     const { url, verifier, state } = await tden.authorizeURL({ scope: 'openid tden_demo_basic_v1' })
//     req.session.tdenVerifier = verifier
//     req.session.tdenState = state
//     res.redirect(url)
//   })
//
//   app.get('/auth/tden/callback', async (req, res) => {
//     const { code, state } = req.query
//     if (state !== req.session.tdenState) return res.status(400).send('state mismatch')
//     const tokens = await tden.exchangeCode({ code: code as string, verifier: req.session.tdenVerifier })
//     const user = await tden.userInfo(tokens.access_token)
//     // user.did, user.is_real_name_verified, user.reputation_score, user.real_name (if granted)
//     ...
//   })

import { pkceChallenge } from './pkce.js'

export interface TDENClientOptions {
  clientId: string
  clientSecret?: string                    // omit for public clients (PKCE only)
  redirectUri: string
  /** Override OIDC issuer; defaults to https://gateway.tden.network */
  issuer?: string
  /** Override discovery URL; defaults to <issuer>/.well-known/openid-configuration */
  discoveryUrl?: string
  /** Override fetch impl (for testing / non-standard runtimes) */
  fetch?: typeof fetch
}

export interface DiscoveryDoc {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  scopes_supported: string[]
  id_token_signing_alg_values_supported: string[]
  code_challenge_methods_supported: string[]
}

export interface AuthorizeURLOptions {
  scope: string                            // e.g. "openid tden_demo_basic_v1"
  state?: string                           // CSRF / continuity; SDK auto-generates if omitted
  nonce?: string                           // OIDC replay defense; auto-generated
}

export interface AuthorizeURLResult {
  url: string
  verifier: string                         // store in session for the callback handler
  state: string
  nonce: string
}

export interface TokenResponse {
  access_token: string
  id_token: string
  token_type: 'Bearer'
  expires_in: number
  scope: string
}

export interface IDTokenClaims {
  iss: string
  sub: string                              // user DID
  aud: string                              // your client_id
  exp: number
  iat: number
  nonce?: string
  did?: string
  is_real_name_verified?: boolean
  reputation_score?: number
  real_name?: string
  wallet_address?: string
  'tden:scene_package_id'?: string
  'tden:scene_package_version'?: string
  'tden:granted_fields'?: string[]
  'tden:auth_methods'?: string[]
  'tden:auth_strength'?: 'high' | 'medium' | 'low'
}

export interface UserInfo extends IDTokenClaims {
  // Same shape as id_token claims — gateway returns one merged document.
}

export interface TokenExchangeOptions {
  code: string
  verifier: string                         // PKCE verifier from authorizeURL()
}

export class TDENClient {
  private opts: Required<TDENClientOptions>
  private discovery?: DiscoveryDoc

  constructor(opts: TDENClientOptions) {
    if (!opts.clientId) throw new Error('TDENClient: clientId required')
    if (!opts.redirectUri) throw new Error('TDENClient: redirectUri required')
    this.opts = {
      clientId: opts.clientId,
      clientSecret: opts.clientSecret ?? '',
      redirectUri: opts.redirectUri,
      issuer: opts.issuer ?? 'https://gateway.tden.network',
      discoveryUrl: opts.discoveryUrl ?? (opts.issuer ?? 'https://gateway.tden.network') + '/.well-known/openid-configuration',
      fetch: opts.fetch ?? fetch.bind(globalThis),
    }
  }

  /** Lazily load + cache the discovery document. */
  async getDiscovery(): Promise<DiscoveryDoc> {
    if (this.discovery) return this.discovery
    const resp = await this.opts.fetch(this.opts.discoveryUrl)
    if (!resp.ok) throw new Error(`discovery: HTTP ${resp.status}`)
    this.discovery = (await resp.json()) as DiscoveryDoc
    return this.discovery
  }

  /**
   * Build the /authorize URL for redirecting the user. Returns the URL plus
   * `verifier`, `state`, `nonce` — RP must persist these to a session and
   * pass `verifier` back to {@link exchangeCode} on the callback.
   */
  async authorizeURL(opts: AuthorizeURLOptions): Promise<AuthorizeURLResult> {
    const disc = await this.getDiscovery()
    const pkce = await pkceChallenge()
    const state = opts.state ?? randomToken()
    const nonce = opts.nonce ?? randomToken()
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.opts.clientId,
      redirect_uri: this.opts.redirectUri,
      scope: opts.scope,
      state,
      nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    })
    return {
      url: `${disc.authorization_endpoint}?${params.toString()}`,
      verifier: pkce.verifier,
      state,
      nonce,
    }
  }

  /**
   * Exchange authorization code for ID + access tokens.
   * Sends client_secret if configured (confidential client), else PKCE-only (public client).
   */
  async exchangeCode(opts: TokenExchangeOptions): Promise<TokenResponse> {
    const disc = await this.getDiscovery()
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: opts.code,
      redirect_uri: this.opts.redirectUri,
      client_id: this.opts.clientId,
      code_verifier: opts.verifier,
    })
    if (this.opts.clientSecret) body.set('client_secret', this.opts.clientSecret)
    const resp = await this.opts.fetch(disc.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    const text = await resp.text()
    if (!resp.ok) throw new Error(`token exchange: HTTP ${resp.status} — ${text}`)
    return JSON.parse(text) as TokenResponse
  }

  /**
   * Decode an id_token without verifying signature.
   * **For verified claims, use verifyIDToken() (Phase B — needs JWKS fetch + Ed25519 verify).**
   */
  decodeIDToken(idToken: string): IDTokenClaims {
    const parts = idToken.split('.')
    if (parts.length !== 3) throw new Error('id_token: not a JWT')
    const payload = parts[1]!
    const decoded = base64UrlDecode(payload)
    return JSON.parse(new TextDecoder().decode(decoded)) as IDTokenClaims
  }

  /** GET /userinfo — current attribute view. */
  async userInfo(accessToken: string): Promise<UserInfo> {
    const disc = await this.getDiscovery()
    const resp = await this.opts.fetch(disc.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (!resp.ok) throw new Error(`userinfo: HTTP ${resp.status}`)
    return (await resp.json()) as UserInfo
  }
}

function randomToken(): string {
  const arr = new Uint8Array(32)
  ;(typeof crypto !== 'undefined' ? crypto : (eval('require'))('node:crypto').webcrypto).getRandomValues(arr)
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('')
}

function base64UrlDecode(s: string): Uint8Array {
  const pad = '='.repeat((4 - (s.length % 4)) % 4)
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/')
  if (typeof atob !== 'undefined') {
    const bin = atob(b64)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  }
  return Uint8Array.from(Buffer.from(b64, 'base64'))
}
