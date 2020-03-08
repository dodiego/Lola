const { validate } = require('./utils')
const argon = require('argon2')
const basicUserSchema = require('../json_schemas/basic_user.json')
const Ajv = require('ajv')
const pino = require('pino')
const { RBAC } = require('fast-rbac')

class HttpError extends Error {
  constructor (message, status) {
    super(message)
    this.status = status
  }
}

async function beforeSave (user, node, rbac) {
  validate(this.ajv, this.validations && this.validations[node._label], node)

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

function beforeRead (user, node, rbac) {
  if (!rbac.can('users', node._label, 'read', { user, node })) {
    return false
  }
  if (node._label === 'users') {
    delete node.password
  }
  return true
}

function beforeDelete (user, node, rbac) {
  if (!beforeRead(user, node, rbac)) {
    throw new HttpError('Unauthorized', 403)
  }
}

function handleGenericError (logger, error) {
  logger.error(error)
  throw new HttpError('Please try again later', 500)
}

function handleErrors (logger, error) {
  if (error instanceof HttpError) {
    throw error
  }
  handleGenericError(logger, error)
}

module.exports = class Controller {
  /**
   *
   * @param {any} konekto
   * @param {import('fast-rbac').RBAC.Options} rbacOptions
   * @param {any} validations
   */
  constructor (konekto, rbacOptions, validations) {
    const schemas = [basicUserSchema]
    if (validations) {
      schemas.push(...Object.values(validations))
    }

    if (!konekto) {
      throw new Error('You must provide a konekto instance as first parameter')
    }

    if (!rbacOptions) {
      throw new Error('You must provide at least an empty object for RBAC')
    }

    const ajv = new Ajv({ schemas, allErrors: true, jsonPointers: true })
    require('ajv-errors')(ajv)
    this.ajv = ajv
    this.konekto = konekto
    this.logger = pino()
    if (!Object.keys(rbacOptions).length) {
      this.rbac = new RBAC({
        roles: {
          '*': { can: ['*'] }
        }
      })
    } else {
      this.rbac = new RBAC(rbacOptions)
    }
  }

  async createUser (user) {
    try {
      validate(this.ajv, basicUserSchema, user)
    } catch (error) {
      this.logger.error(error)
      throw new HttpError(error.message, 400)
    }
    user.password = await argon.hash(user.password)
    user._label = 'users'
    try {
      return await this.konekto.save(user, {
        hooks: {
          beforeSave: node => beforeSave(user, node, this.rbac)
        }
      })
    } catch (error) {
      this.logger.error(error)
      throw new HttpError("Coudn't create the user, please try again later", 500)
    }
  }

  async findUser (payload) {
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
      throw new HttpError('User not found', 404)
    }
    if (!(await argon.verify(payload.password, user.password))) {
      throw new HttpError('invalid password', 400)
    }
    delete user.password

    return user
  }

  async save (user, payload) {
    try {
      return await this.konekto.save(payload, {
        hooks: {
          beforeSave: node => beforeSave(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleGenericError(this.logger, error)
    }
  }

  async findById (user, id) {
    try {
      return await this.konekto.findById(id, {
        hooks: {
          beforeRead: node => beforeRead(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleGenericError(this.logger, error)
    }
  }

  async findByQueryObject (user, queryObject) {
    try {
      return await this.konekto.findByQueryObject(queryObject, {
        hooks: {
          beforeRead: node => beforeRead(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleGenericError(this.logger, error)
    }
  }

  async deleteByQueryObject (user, queryObject) {
    try {
      return await this.konekto.deleteByQueryObject(queryObject, {
        hooks: {
          beforeRead: node => beforeDelete(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleErrors(this.logger, error)
    }
  }

  async deleteById (user, id) {
    try {
      return await this.konekto.deleteById(id, {
        hooks: {
          beforeRead: node => beforeDelete(user, node, this.rbac)
        }
      })
    } catch (error) {
      handleErrors(this.logger, error)
    }
  }
}
