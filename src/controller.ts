import { validate } from './utils'
import argon from 'argon2'
import basicUserSchema from '../json_schemas/basic_user.json'
import Ajv from 'ajv'
import pino, { Logger } from 'pino'
import RBAC from 'fast-rbac'

class HttpError extends Error {
  constructor (message: string, public status: number) {
    super(message)
  }
}

function beforeRead (user: any, node: any, rbac: RBAC) {
  if (!rbac.can('users', node._label, 'read', { user, node })) {
    return false
  }
  if (node._label === 'users') {
    delete node.password
  }
  return true
}

function beforeDelete (user: any, node: any, rbac: RBAC) {
  if (!beforeRead(user, node, rbac)) {
    throw new HttpError('Unauthorized', 403)
  }
}

function handleGenericError (logger: Logger, error: Error) {
  logger.error(error)
  throw new HttpError('Please try again later', 500)
}

function handleErrors (logger: Logger, error: Error) {
  if (error instanceof HttpError) {
    throw error
  }
  handleGenericError(logger, error)
}

export = class Controller {
  private ajv: Ajv.Ajv
  private logger = pino()
  constructor (private validations: any, private konekto: any, private rbac: RBAC) {
    const schemas: any[] = [basicUserSchema]
    if (validations) {
      schemas.push(...Object.values(validations))
    }

    const ajv = new Ajv({ schemas, allErrors: true, jsonPointers: true })
    require('ajv-errors')(ajv)
    this.ajv = ajv
  }

  async createUser (user: any) {
    try {
      validate(this.ajv, basicUserSchema, user)
    } catch (error) {
      this.logger.error(error)
      throw {
        status: 400,
        message: error.message
      }
    }
    user.password = await argon.hash(user.password)
    user._label = 'users'
    try {
      return await this.konekto.save(user)
    } catch (error) {
      this.logger.error(error)
      throw {
        status: 500,
        message: "Coudn't create the user, please try again later"
      }
    }
  }

  async findUser (payload: any) {
    const user = await this.konekto.findOneByQueryObject({
      _label: 'users',
      _where: {
        filter: '{this}.username = :username',
        params: {
          username: payload.username
        }
      }
    })

    if (!user) {
      throw {
        status: 404,
        message: 'User not found'
      }
    }
    if (!(await argon.verify(payload.password, user.password))) {
      throw {
        status: 400,
        message: 'invalid password'
      }
    }
    delete user.password

    return user
  }

  async save (user: any, payload: any) {
    try {
      return await this.konekto.save(payload, {
        hooks: {
          beforeSave: async (node: any) => {
            validate(this.ajv, this.validations?.[node._label], node)

            const nodeDb = await this.konekto.findOneByQueryObject({
              _label: node._label,
              _where: { filter: '{this}._id = :id', params: { id: node._id } }
            })

            if (nodeDb) {
              return this.rbac.can('users', node._label, 'update', { user, node })
            }
            if (!this.rbac.can('users', node._label, 'create', { user, node })) {
              return false
            }
            if (node._id !== user._id) {
              node.user_id = user._id
            }
            return true
          }
        }
      })
    } catch (error) {
      handleGenericError(this.logger, error)
    }
  }

  async findById (user: any, id: string) {
    try {
      return await this.konekto.findById(id, {
        hooks: {
          beforeRead: (node: any) => beforeRead(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleGenericError(this.logger, error)
    }
  }

  async findByQueryObject (user: any, queryObject: any) {
    try {
      return await this.konekto.findByQueryObject(queryObject, {
        hooks: {
          beforeRead: (node: any) => beforeRead(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleGenericError(this.logger, error)
    }
  }

  async deleteByQueryObject (user: any, queryObject: any) {
    try {
      return await this.konekto.deleteByQueryObject(queryObject, {
        hooks: {
          beforeRead: (node: any) => beforeDelete(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleErrors(this.logger, error)
    }
  }

  async deleteById (user: any, id: string) {
    try {
      return await this.konekto.deleteById(id, {
        hooks: {
          beforeRead: (node: any) => beforeDelete(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleErrors(this.logger, error)
    }
  }
}
