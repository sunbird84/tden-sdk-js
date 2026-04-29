// Example: Express server using @tden/sdk for "Sign in with TDEN".
//
// Run:
//   npm install express express-session @tden/sdk
//   node examples/express-server.mjs
//
// Pre-req: register a scene package via the TDEN portal and copy
//          client_id + client_secret + add http://localhost:3000/auth/tden/callback
//          to redirect_uris.

import express from 'express'
import session from 'express-session'
import { TDENClient } from '@tden/sdk'

const tden = new TDENClient({
  clientId: process.env.TDEN_CLIENT_ID || 'tden_demo_basic_v1',
  clientSecret: process.env.TDEN_CLIENT_SECRET || '',
  redirectUri: 'http://localhost:3000/auth/tden/callback',
})

const app = express()
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, sameSite: 'lax' },
}))

app.get('/', (req, res) => {
  if (req.session.user) {
    res.send(`<h1>Hello ${req.session.user.real_name || req.session.user.did}</h1>
              <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
              <a href="/logout">Sign out</a>`)
  } else {
    res.send(`<a href="/auth/tden/login">Sign in with TDEN</a>`)
  }
})

app.get('/auth/tden/login', async (req, res, next) => {
  try {
    const { url, verifier, state, nonce } = await tden.authorizeURL({
      scope: 'openid tden_demo_basic_v1',
    })
    req.session.tdenVerifier = verifier
    req.session.tdenState = state
    req.session.tdenNonce = nonce
    res.redirect(url)
  } catch (e) { next(e) }
})

app.get('/auth/tden/callback', async (req, res, next) => {
  try {
    const { code, state } = req.query
    if (state !== req.session.tdenState) return res.status(400).send('state mismatch')
    const tokens = await tden.exchangeCode({
      code: String(code),
      verifier: req.session.tdenVerifier,
    })
    const user = await tden.userInfo(tokens.access_token)
    if (user.nonce !== req.session.tdenNonce) return res.status(400).send('nonce mismatch')
    req.session.user = user
    res.redirect('/')
  } catch (e) { next(e) }
})

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'))
})

app.listen(3000, () => console.log('TDEN demo at http://localhost:3000'))
