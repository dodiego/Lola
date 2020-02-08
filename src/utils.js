const Konekto = require('konekto')
const jwt = require('jsonwebtoken')
const { promisify } = require('util')
const jwtSign = promisify(jwt.sign)
const jwtVerify = promisify(jwt.verify)
const Ajv = require('ajv')
const ajv = new Ajv({ allErrors: true, jsonPointers: true })
require('ajv-errors')(ajv)
const jwtSchema = require('../json_schemas/jwt_config.json')

function validate (schema, object) {
  const result = ajv.validate(schema, object)
  if (!result) {
    throw new Error(ajv.errors.map(e => e.message).join('\n'))
  }
}

function onAborted (res) {
  res.onAborted(() => {
    res.aborted = true
  })
}
function respond (res, result) {
  if (!res.aborted) {
    res.end(JSON.stringify(result))
  }
}

/**
 *
 * @param {import('uWebSockets.js').HttpResponse} res
 */
function readBody (res) {
  let buffer
  return new Promise((resolve, reject) => {
    res.onData((ab, isLast) => {
      const chunk = Buffer.from(ab)
      if (isLast) {
        let json
        if (buffer) {
          try {
            json = JSON.parse(Buffer.concat([buffer, chunk]))
          } catch (e) {
            res.close()
            reject(e)
          }

          resolve(json)
        } else {
          try {
            json = JSON.parse(chunk)
          } catch (e) {
            res.close()
            reject(e)
          }
          resolve(json)
        }
      } else {
        if (buffer) {
          buffer = Buffer.concat([buffer, chunk])
        } else {
          buffer = Buffer.concat([chunk])
        }
      }
    })
  })
}

class TokenHelper {
  constructor (jwtConfig, konektoInstance) {
    validate(jwtSchema, jwtConfig)
    if (!(konektoInstance instanceof Konekto)) {
      throw new Error('You must provide a valid Konekto instance')
    }
    this._jwtConfig = jwtConfig
    this._konekto = konektoInstance
  }

  /**
   *
   * @param {import('uWebSockets.js').HttpResponse} res
   * @param {String} _id
   */
  async getToken (res, _id) {
    let response
    try {
      const token = await jwtSign({ _id }, this._jwtConfig.secret, this._jwtConfig.options)
      response = { token }
    } catch (error) {
      response = { message: "couldn't login, please try again" }
      res.writeStatus('500')
    }
    respond(res, JSON.stringify(response))
  }

  async getUserFromToken (token) {
    const user = await jwtVerify(token, this._jwtConfig.secret)
    const userDb = await this._konekto.findOneByQueryObject({
      _label: 'users',
      _where: { filter: '{this}._id = :id', params: { id: user._id } }
    })
    if (!userDb) {
      throw new Error("User does't exist")
    }
    return userDb
  }

  /**
   *
   * @param {import('uWebSockets.js').HttpResponse} res
   * @param {import('uWebSockets.js').HttpRequest} req
   */
  async authenticate (res, token) {
    try {
      return await this.getUserFromToken(token)
    } catch (error) {
      respond(res.writeStatus('401'))
      throw error
    }
  }
}

module.exports = {
  onAborted,
  respond,
  readBody,
  TokenHelper
}
