// @tden/sdk — entry point
// 公开 API:OIDC client + scenepkg helpers + webhook verifier
// Public API: OIDC client + scene-package helpers + webhook verifier

export { TDENClient } from './client.js'
export type {
  TDENClientOptions,
  AuthorizeURLOptions,
  TokenExchangeOptions,
  IDTokenClaims,
  UserInfo,
} from './client.js'

export { ScenePackages } from './scenepkg.js'
export type { ScenePackage, FieldRequest } from './scenepkg.js'

export { verifyWebhook } from './webhook.js'
export type { WebhookEvent } from './webhook.js'

export { verifyAccessReceipt, findReceiptGaps } from './receipt.js'
export type { AccessReceipt, JWK, JWKS, VerifyResult } from './receipt.js'

// PKCE 工具(让 RP 自己用) / PKCE helpers (consumers may use directly)
export { pkceChallenge } from './pkce.js'

// Default fixed endpoints
export const TDEN_DEFAULTS = {
  issuer: 'https://gateway.tden.network',
  discovery: 'https://gateway.tden.network/.well-known/openid-configuration',
  scenepkgList: 'https://gateway.tden.network/api/scenepackages',
} as const
