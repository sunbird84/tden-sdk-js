// @tden/sdk — Access Receipt verifier (Phase A2.7+).
//
// 创意特性 / Innovation:
// 每次第三方查询用户数据,gateway 给用户的访问日志加 Ed25519 签名。
// 用户(或第三方审计)用此 helper + gateway JWKS 独立验证回执:
//   - 内容没被篡改
//   - 签名是 gateway 自己签的(不是冒充)
//   - gateway 没法静默隐瞒一次访问(否则就没回执)
//
// 这是 TDEN 的"用户主权"证据机制 — 真实地把 audit 控制权交给用户。
//
// Innovation: gateway signs every DataAccessLog with its OIDC Ed25519 key.
// Users (or third-party auditors) call verifyAccessReceipt with the gateway's
// public JWKS. Confirms (a) the log contents weren't tampered, (b) the signature
// is gateway's, (c) the gateway can't silently delete a receipt — anything
// missing is detectable as a "gap" in receipts.
//
// Phase B 计划 / Phase B plan:
// - 链上锚定 receipts merkle root,任意节点都能复检完整性
// - 多设备 receipt 同步(本地缓存对账)

export interface AccessReceipt {
  log: {
    log_id: string
    auth_id: string
    package_id: string
    package_name: string
    developer_uid: string
    user_uid: string
    fields_accessed: string[]
    access_type: string
    remote_ip: string
    accessed_at: number
  }
  /** Exact bytes that were signed — DO NOT modify before verifying. */
  canonical_json: string
  /** base64url-no-pad of EdDSA(SHA-256(canonical_json)) */
  signature_b64: string
  /** Key id — look up matching JWK in gateway's JWKS */
  kid: string
  /** Always "EdDSA" for Phase A2.7 */
  alg: string
  /** Suggested JWKS endpoint */
  jwks_url: string
}

export interface JWK {
  kty: string
  crv?: string
  x?: string
  kid?: string
  alg?: string
}

export interface JWKS {
  keys: JWK[]
}

export interface VerifyResult {
  ok: boolean
  reason?: string
}

/**
 * Verify an access receipt against a JWKS.
 *
 * @param receipt — issued by gateway /api/me/access-receipts
 * @param jwks    — fetched from `${gateway}/oauth/jwks`
 * @returns       — { ok: true } or { ok: false, reason: '...' }
 */
export async function verifyAccessReceipt(
  receipt: AccessReceipt,
  jwks: JWKS,
): Promise<VerifyResult> {
  if (receipt.alg !== 'EdDSA') {
    return { ok: false, reason: `unsupported alg: ${receipt.alg}` }
  }
  const jwk = jwks.keys.find((k) => k.kid === receipt.kid)
  if (!jwk) {
    return { ok: false, reason: `key id ${receipt.kid} not in JWKS` }
  }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) {
    return { ok: false, reason: 'JWK is not an Ed25519 OKP key' }
  }
  const pub = base64UrlDecode(jwk.x)
  if (pub.length !== 32) {
    return { ok: false, reason: `Ed25519 public key wrong length: ${pub.length}` }
  }
  const sig = base64UrlDecode(receipt.signature_b64)
  if (sig.length !== 64) {
    return { ok: false, reason: `signature wrong length: ${sig.length}` }
  }
  const msg = new TextEncoder().encode(receipt.canonical_json)
  const digest = await sha256(msg)

  const subtle = getSubtle()
  // WebCrypto Ed25519 (Edwards Curve via 'Ed25519' algorithm — supported in Node 20+ + modern browsers).
  try {
    const cryptoKey = await subtle.importKey(
      'raw',
      pub as unknown as BufferSource,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    const ok = await subtle.verify(
      { name: 'Ed25519' },
      cryptoKey,
      sig as unknown as BufferSource,
      digest as unknown as BufferSource,
    )
    return ok ? { ok: true } : { ok: false, reason: 'signature mismatch' }
  } catch (e) {
    return { ok: false, reason: `webcrypto: ${(e as Error).message}` }
  }
}

/**
 * Detect gaps in a sorted list of receipts — useful for "did the gateway
 * silently delete one?" check. Pass receipts in chronological order;
 * returns indices where consecutive receipts have a > 1h gap (heuristic;
 * tunable).
 */
export function findReceiptGaps(receipts: AccessReceipt[], gapSeconds = 3600): number[] {
  const gaps: number[] = []
  for (let i = 1; i < receipts.length; i++) {
    if (receipts[i]!.log.accessed_at - receipts[i - 1]!.log.accessed_at > gapSeconds) {
      gaps.push(i)
    }
  }
  return gaps
}

// ── helpers ───────────────────────────────────────────────────────────────

function getSubtle(): SubtleCrypto {
  if (typeof globalThis.crypto !== 'undefined' && (globalThis.crypto as any).subtle) {
    return globalThis.crypto.subtle
  }
  const nodeCrypto = (eval('require'))('node:crypto')
  return (nodeCrypto.webcrypto || nodeCrypto).subtle as SubtleCrypto
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = getSubtle()
  const buf = await subtle.digest('SHA-256', bytes as unknown as BufferSource)
  return new Uint8Array(buf)
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
