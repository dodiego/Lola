//@ts-ignore
import Konekto from 'konekto'
import jwt from 'jsonwebtoken'
import { HttpResponse } from 'uWebSockets.js'
import Ajv, { ValidateFunction } from 'ajv'
import jwtSchema from '../json_schemas/jwt_config.json'
import { promisify } from 'util'
import ajvErrors from 'ajv-errors'

const jwtSign = promisify(jwt.sign)
const jwtVerify = promisify(jwt.verify)
const ajv = new Ajv({ allErrors: true, jsonPointers: true })
ajvErrors(ajv)

export function validate (validator: ValidateFunction, validations: any, label: string, json: any): void {
  if (validations?.[label]) {
    const result = validator(json)
    if (!result) {
      throw new Error(validator?.errors?.map(e => e.message).join('\n'))
    }
  }
}

export function onAborted (res: HttpResponse): void {
  res.onAborted(() => {
    res.aborted = true
  })
}
export function respond (res: HttpResponse, result?: object): void {
  if (!res.aborted) {
    res.end(JSON.stringify(result))
  }
}

export function readBody (res: HttpResponse): Promise<any> {
  let buffer: Uint8Array
  return new Promise((resolve, reject) => {
    res.onData((ab, isLast) => {
      const chunk = Buffer.from(ab)
      if (isLast) {
        let json
        if (buffer) {
          try {
            json = JSON.parse((Buffer.concat([buffer, chunk]) as unknown) as string)
          } catch (e) {
            res.close()
            reject(e)
          }

          resolve(json)
        } else {
          try {
            json = JSON.parse((chunk as unknown) as string)
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

export interface JwtConfig {
  options?: jwt.SignOptions;
  secret: string;
}

export class TokenHelper {
  constructor (private _jwtConfig: JwtConfig, private _konekto: Konekto) {
    const result = ajv.validate(jwtSchema, _jwtConfig)
    if (!result) {
      throw new Error(ajv?.errors?.map(e => e.message).join('\n'))
    }
    if (!(_konekto instanceof Konekto)) {
      throw new Error('You must provide a valid Konekto instance')
    }
  }

  async getToken (res: HttpResponse, _id: string): Promise<void> {
    let response
    try {
      const token = await jwtSign({ _id }, this._jwtConfig.secret)
      response = { token }
    } catch (error) {
      response = { message: "couldn't login, please try again" }
      res.writeStatus('500')
    }
    respond(res, response)
  }

  async getUserFromToken (token: string): Promise<any> {
    const user: any = await jwtVerify(token, this._jwtConfig.secret)
    const userDb = await this._konekto.findOneByQueryObject({
      _label: 'users',
      _where: { filter: '{this}._id = :id', params: { id: user._id } }
    })
    if (!userDb) {
      throw new Error("User does't exist")
    }
    return userDb
  }

  async authenticate (res: HttpResponse, token: string): Promise<any> {
    try {
      return this.getUserFromToken(token)
    } catch (error) {
      respond(res.writeStatus('401'))
      throw error
    }
  }
}
