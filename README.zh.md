# @tden/sdk

> 英文版:[README.md](README.md)

> 状态:**Phase A2.6** —— OIDC 客户端 + 场景包读取 + Webhook 校验已交付;完整集成测试与 Phase B JWKS 验证 id_token 待发布。

TDEN 的 JavaScript SDK,用于"用 TDEN 登录"和场景包管理。可在 Node.js(服务端 OAuth 流程)和浏览器(同意 UX / 被动属性读取)中使用。

## 安装

```bash
npm install @tden/sdk
```

## 快速开始(服务端 OAuth code flow)

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

完整可运行示例见 [`examples/express-server.mjs`](./examples/express-server.mjs)。

## 场景包读取

```ts
import { ScenePackages } from '@tden/sdk'

const pkgs = new ScenePackages()
const list = await pkgs.listApproved()      // every approved package globally
const one = await pkgs.get('tden_demo_basic_v1')
```

## Webhook 校验

当用户撤销 / 重新授权 / 同意过期时,TDEN 会向你场景包的 `webhook_url` 发起 POST。在改写状态前请先验证签名:

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

> **注意:** 网关侧 webhook 投递(Phase A2.4)仍在路线图上。SDK 校验已提前就绪,RP 可放心集成。

## API 稳定性

| API | 稳定性 | 备注 |
|---|---|---|
| `TDENClient.authorizeURL` | Stable | 兼容 RFC 6749 + 7636 + OIDC core |
| `TDENClient.exchangeCode` | Stable | 同时支持 PKCE-only public 与 `client_secret_post` confidential |
| `TDENClient.decodeIDToken` | Stable | **不验证签名** —— Phase B 增加 verifyIDToken() 通过 JWKS 验签 |
| `TDENClient.userInfo` | Stable | GET /oauth/userinfo |
| `ScenePackages.*` | Stable | 只读 —— 公开端点 |
| `verifyWebhook` | Stable | HMAC-SHA256,常数时间比较 |

## 浏览器使用

SDK 是 ESM,可在现代浏览器中使用。典型场景:

- 在首页"用 X 登录"UI 中读取场景包列表
- 显示登录前的属性预览("此站将看到:实名、年龄段")
- 处理同意 UX 集成

**不要把 `clientSecret` 放进浏览器代码。** 使用 `client_secret_post` 的 OAuth code flow 仅限服务端。浏览器登录请改用公共客户端变体(仅 PKCE,无 secret)。

## 安全

详见 [`tden-spec/spec/security-threat-model.md`](https://github.com/sunbird84/tden-spec/blob/master/spec/security-threat-model.md) §1.9。

## 许可证

AGPL-3.0。
