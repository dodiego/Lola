import { JwtConfig } from './utils'
import RBAC from 'fast-rbac'
import { ConnectionConfig } from 'pg'

import Server from './server'
// @ts-ignore
import Konekto from 'konekto'

export = class Lola {
  konekto: any
  server: any
  _seeded: boolean = false

  constructor (jwtConfig: JwtConfig, rbacOptions: RBAC.Options, connectionConfig: ConnectionConfig) {
    const konekto = new Konekto(connectionConfig)
    const server = new Server({ konekto, rbacOptions, jwtConfig })

    this.konekto = konekto
    this.server = server
  }

  async seed (graphName: string, schema: any, seedFn = async function (_: any) {}) {
    if (!graphName || typeof graphName !== 'string') {
      throw new Error('graphName must be a string')
    }
    await this.konekto.connect()
    await this.konekto.createGraph(graphName)
    await this.konekto.setGraph(graphName)
    await this.konekto.createSchema(schema)
    await seedFn(this.konekto)
    this._seeded = true
  }

  async start (hostname: string, port: number) {
    if (!this._seeded) {
      throw new Error('You need to seed the database before starting the server')
    }
    await this.server.listen(hostname, port)
  }
}
