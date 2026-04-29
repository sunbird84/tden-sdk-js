// @tden/sdk — Webhook signature verifier.
//
// 当用户撤销 / 重新授权 / 同意到期时,gateway 会以 HMAC-SHA256 签名 POST 到
// 场景包注册的 webhook_url。RP 必须在处理事件前用 SDK 验签,避免被伪造请求修改用户态。
//
// When user revokes/regrants/consent expires, gateway POSTs to the package's
// webhook_url with HMAC-SHA256 signature. RP must verify before mutating
// user state — otherwise spoofed requests can flip auth flags.
//
// Phase A2.4(Coming):webhook 实际投递逻辑还在 gateway 路线图上。这里 SDK 提前
// 准备好 verifier API,部署上线立刻可用。
//
// Phase A2.4 (TBD): gateway-side webhook delivery is on roadmap. This SDK
// verifier is ready ahead of time for forward-compat.

export interface WebhookEvent {
  event: 'consent.granted' | 'consent.revoked' | 'consent.expired' | 'package.revoked'
  grant_id?: string
  package_id: string
  user_did?: string
  timestamp: number
  reason?: string
}

export interface VerifyResult {
  ok: boolean
  event?: WebhookEvent
  error?: string
}

/**
 * Verify a TDEN webhook delivery.
 *
 * @param body raw request body bytes (DO NOT JSON.parse before this — signature is over raw bytes)
 * @param signatureHeader value of `X-TDEN-Signature` header (format: `sha256=<hex>`)
 * @param secret the per-package webhook secret (issued at approval time, store in your env)
 *
 * Returns { ok: true, event } if signature matches, { ok: false, error } otherwise.
 */
export async function verifyWebhook(
  body: string | Uint8Array,
  signatureHeader: string,
  secret: string,
): Promise<VerifyResult> {
  if (!signatureHeader) return { ok: false, error: 'missing X-TDEN-Signature header' }
  const m = /^sha256=([0-9a-f]+)$/i.exec(signatureHeader.trim())
  if (!m) return { ok: false, error: 'malformed signature header' }
  const expectedHex = m[1]!.toLowerCase()

  // Normalise body to a Uint8Array backed by a plain ArrayBuffer (not SAB).
  // TS 5+ tightened BufferSource to reject SharedArrayBuffer; copy-into-new
  // Uint8Array guarantees a plain ArrayBuffer.
  const bytes = typeof body === 'string'
    ? new TextEncoder().encode(body)
    : new Uint8Array(body)
  const secretBytes = new TextEncoder().encode(secret)
  const subtle = getSubtle()
  const key = await subtle.importKey(
    'raw',
    secretBytes as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await subtle.sign('HMAC', key, bytes as unknown as BufferSource)
  const actualHex = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('')

  // Constant-time comparison
  if (!constantTimeEqual(actualHex, expectedHex)) {
    return { ok: false, error: 'signature mismatch' }
  }

  let event: WebhookEvent
  try {
    event = JSON.parse(typeof body === 'string' ? body : new TextDecoder().decode(body))
  } catch {
    return { ok: false, error: 'invalid JSON body' }
  }
  return { ok: true, event }
}

function getSubtle(): SubtleCrypto {
  if (typeof globalThis.crypto !== 'undefined' && (globalThis.crypto as any).subtle) {
    return globalThis.crypto.subtle
  }
  const nodeCrypto = (eval('require'))('node:crypto')
  return (nodeCrypto.webcrypto || nodeCrypto).subtle as SubtleCrypto
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}
