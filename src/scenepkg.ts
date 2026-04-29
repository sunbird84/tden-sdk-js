// @tden/sdk — Scene-package read helpers.
//
// 用法:展示给用户"这个 RP 申请了哪些字段、要做啥",或在 RP 后端做策略门控。
// Use case: render the package's purpose / requested fields to the user
// before login, or gate features on consent grants in your backend.

export interface FieldRequest {
  tag: string
  required: boolean
  justification: string
}

export interface ScenePackage {
  package_id: string
  package_name: string
  version: string
  developer_did: string
  institution_type: string
  institution_verified?: boolean
  fields: FieldRequest[]
  purpose: string
  lawful_basis: string
  auth_types: string[]
  max_validity_seconds: number
  max_queries_per_day: number
  redirect_uris: string[]
  sensitivity_level: 'normal' | 'sensitive'
  review_status: string
  client_id?: string
  approved_at?: number
  created_at: number
  updated_at: number
}

export interface ScenePackagesOptions {
  /** Override gateway URL; defaults to https://gateway.tden.network */
  gatewayUrl?: string
  fetch?: typeof fetch
}

export class ScenePackages {
  private gatewayUrl: string
  private fetch: typeof fetch

  constructor(opts: ScenePackagesOptions = {}) {
    this.gatewayUrl = opts.gatewayUrl ?? 'https://gateway.tden.network'
    this.fetch = opts.fetch ?? fetch.bind(globalThis)
  }

  /** GET /api/scenepackages — list every approved package globally. */
  async listApproved(): Promise<{ packages: ScenePackage[]; count: number }> {
    const resp = await this.fetch(`${this.gatewayUrl}/api/scenepackages`)
    if (!resp.ok) throw new Error(`listApproved: HTTP ${resp.status}`)
    return (await resp.json()) as { packages: ScenePackage[]; count: number }
  }

  /** GET /api/scenepackages/{id}. Returns null if not found / not approved. */
  async get(packageId: string): Promise<ScenePackage | null> {
    const resp = await this.fetch(
      `${this.gatewayUrl}/api/scenepackages/${encodeURIComponent(packageId)}`,
    )
    if (resp.status === 404) return null
    if (!resp.ok) throw new Error(`get: HTTP ${resp.status}`)
    return (await resp.json()) as ScenePackage
  }
}
