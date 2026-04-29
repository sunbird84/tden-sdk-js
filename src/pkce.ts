// PKCE (RFC 7636) — Code-challenge generator for the OAuth `code` flow.
// 工作原理:
//   1. 客户端生成 verifier(43-128 字节随机串)
//   2. challenge = base64url(SHA-256(verifier))
//   3. 把 challenge 放到 /authorize 请求,verifier 留在 RP 后端
//   4. /token 时把 verifier 提交,网关重算 SHA-256(verifier) 与 challenge 比对
// 防止授权码被中间人偷走后被任意 RP 兑换。
//
// PKCE prevents auth-code theft + replay.

export interface PKCEPair {
  verifier: string
  challenge: string
  method: 'S256'
}

const VERIFIER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'

/**
 * Generate a fresh PKCE verifier + S256 challenge.
 * Works in both Node.js (uses webcrypto.subtle) and browsers.
 */
export async function pkceChallenge(verifierLen = 64): Promise<PKCEPair> {
  if (verifierLen < 43 || verifierLen > 128) {
    throw new Error('PKCE verifier length must be 43-128')
  }
  const cryptoSubtle = getCrypto()
  const arr = new Uint8Array(verifierLen)
  cryptoSubtle.getRandomValues(arr)
  let verifier = ''
  for (let i = 0; i < arr.length; i++) {
    verifier += VERIFIER_CHARS[arr[i]! % VERIFIER_CHARS.length]
  }
  const enc = new TextEncoder().encode(verifier)
  const hash = await cryptoSubtle.subtle.digest('SHA-256', enc)
  const challenge = base64UrlEncode(new Uint8Array(hash))
  return { verifier, challenge, method: 'S256' }
}

function getCrypto(): Crypto {
  // Browser
  if (typeof globalThis.crypto !== 'undefined' && (globalThis.crypto as any).subtle) {
    return globalThis.crypto
  }
  // Node 18+: webcrypto is at node:crypto.webcrypto and globalThis.crypto in newer versions
  // Use eval to avoid bundling Node module in browser builds.
  const nodeCrypto = (eval('require'))('node:crypto')
  return (nodeCrypto.webcrypto || nodeCrypto) as Crypto
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  const b64 = (typeof btoa !== 'undefined' ? btoa : (s: string) => Buffer.from(s, 'binary').toString('base64'))(bin)
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}
