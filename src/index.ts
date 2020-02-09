import { JwtConfig } from './utils'
import RBAC from 'fast-rbac'
import { ConnectionConfig } from 'pg'

import Server from './server'
//@ts-ignore
import Konekto from 'konekto'

interface LolaConfig {
  jwtConfig: JwtConfig;
  rbacOptions: RBAC.Options;
  connectionConfig?: ConnectionConfig;
  validations?: any;
}

export = class Lola {
  private konekto: any
  private server: Server
  private _seeded = false

  constructor ({ jwtConfig, rbacOptions, connectionConfig, validations }: LolaConfig) {
    const konekto = new Konekto(connectionConfig)
    const server = new Server({ konekto, rbacOptions, jwtConfig, validations })

    this.konekto = konekto
    this.server = server
  }
// {
//   graphName,
//     schema,
//     seedFn = async function (_: any) { }
// }: {
//   graphName: string
//   schema ?: any
//   seedFn ?: (_: any) => Promise<void>
//   }) {

  async seed({graphName, schema, seedFn}: {graphName: string; schema: any; seedFn?: (_: any) => Promise<void>}): Promise<void> {
    if (!graphName || typeof graphName !== 'string') {
      throw new Error('graphName must be a string')
    }
    if (!schema) {
      schema = { _label: 'users' }
    } else {
      schema = [schema, { _label: 'users' }]
    }
    await this.setup(graphName, schema)

    if (seedFn)
      await seedFn(this.konekto)

    this._seeded = true
  }

  async start (hostname: string, port: number): Promise<void> {
    if (!this._seeded) {
      throw new Error('You need to seed the database before starting the server')
    }
    await this.server.listen(hostname, port)
  }

  async setup(graphName: string, schema: any): Promise<void> {
    [this.konekto.connect(), this.konekto.createGraph(graphName),
    this.konekto.setGraph(graphName), this.konekto.createSchema(schema)]
    .map(async promise => await promise)
  }

    stop(): void {
    this.server.disconnect()
  }
}
