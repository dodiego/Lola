const jwt = require('jsonwebtoken')
const jwtSchema = require('../json_schemas/jwt_config.json')
const Ajv = require('ajv')

const { promisify } = require('util')
const jwtSign = promisify(jwt.sign)
const jwtVerify = promisify(jwt.verify)

function validate (validator, schema, json) {
  if (schema) {
    const result = validator.validate(schema, json)
    if (!result) {
      throw new Error(validator && validator.errors && validator.errors.map(e => e.message).join('\n'))
    }
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
  /**
   *
   * @param {import('./index').JwtConfig} _jwtConfig
   * @param {any} _konekto
   */
  constructor (_jwtConfig, _konekto) {
    const ajv = new Ajv({ allErrors: true, jsonPointers: true })
    this._jwtConfig = _jwtConfig
    this._konekto = _konekto
    require('ajv-errors')(ajv)
    validate(ajv, jwtSchema, _jwtConfig)
  }

  async getToken (res, _id) {
    let response
    try {
      const token = await jwtSign({ _id }, this._jwtConfig.secret, this._jwtConfig.options)
      response = { token }
    } catch (error) {
      response = { message: "couldn't login, please try again" }
      res.writeStatus('500')
    }
    respond(res, response)
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
  validate,
  onAborted,
  respond,
  readBody,
  TokenHelper
}
