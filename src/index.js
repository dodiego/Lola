const Server = require('./server')
const Konekto = require('konekto')
module.exports = class Lola {
  constructor (jwtConfig, rbac, connectionConfig) {
    const konekto = new Konekto(connectionConfig)
    const server = new Server({ konekto, rbac, jwtConfig })

    this.konekto = konekto
    this.server = server
  }

  async seed (graphName, schema, seedFn = function () {}) {
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

  async start (hostname, port) {
    if (!this._seeded) {
      throw new Error('You need to seed the database before starting the server')
    }
    await this.server.listen(hostname, port)
  }
}
