const Server = require('./server')
const Konekto = require('konekto')
module.exports = class Lola {
  /**
   *
   * @param {any} connectionConfig
   * @param {import('fast-rbac').RBAC} rbac
   * @param {*} jwtConfig
   */
  constructor (connectionConfig, rbac, jwtConfig) {
    const konekto = new Konekto(connectionConfig)
    const server = new Server({ konekto, rbac, jwtConfig })

    this.konekto = konekto
    this.server = server
  }

  async seed (graphName, schema, seedFn = function () {}) {
    await this.konekto.connect()
    await this.konekto.createGraph(graphName)
    await this.konekto.setGraph(graphName)
    await this.konekto.createSchema(schema)
    await seedFn(this.konekto)
    this._sedeed = true
  }

  async start (hostname, port) {
    if (!this._sedeed) {
      throw new Error('You need to seed the database before starting the server')
    }
    await this.server.listen(hostname, port)
  }
}
