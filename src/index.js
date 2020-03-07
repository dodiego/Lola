const Server = require('./server')
const Konekto = require('konekto')

module.exports = class Lola {
  /**
   *
   * @param {import('./index').LolaConfig} config
   */
  constructor ({ jwtConfig, rbacOptions, connectionConfig, validations }) {
    const konekto = new Konekto(connectionConfig)
    const server = new Server({ konekto, rbacOptions, jwtConfig, validations })

    this.konekto = konekto
    this.server = server
  }

  async seed ({ graphName, schema, seedFn = async function () {} }) {
    if (!graphName || typeof graphName !== 'string') {
      throw new Error('graphName must be a string')
    }
    if (!schema) {
      schema = { _label: 'users' }
    } else {
      schema = [schema, { _label: 'users' }]
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

  stop () {
    this.server.disconnect()
  }
}
