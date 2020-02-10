import { validate } from './utils'
import bcrypt from 'bcrypt'
import basicUserSchema from '../json_schemas/basic_user.json'
import Ajv from 'ajv'
import { Logger } from 'pino'
import RBAC from 'fast-rbac'

function beforeRead (user: any, node: any, rbac: RBAC) {
  if (!rbac.can('users', node._label, 'read', { user, node })) {
    return false
  }
  if (node._label === 'users') {
    delete node.password
  }
  return true
}

export = class Controller {
  private ajv: Ajv.Ajv
  constructor (private validations: any, private konekto: any, private logger: Logger, private rbac: RBAC) {
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
    const saltRounds = 10
    user.password = await bcrypt.hash(user.password, saltRounds)
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
    if (!(await bcrypt.compare(payload.password, user.password))) {
      throw {
        status: 400,
        message: 'invalid password'
      }
    }
    delete user.password

    return user
  }

  async save (user: any, payload: any) {
    return this.konekto.save(payload, {
      hooks: {
        beforeSave: async (node: any) => {
          validate(this.ajv, this.validations?.[node._label], node)

          const nodeDb = await this.konekto.findOneByQueryObject({
            _label: node._label,
            _where: { filter: '{this}._id = :id', params: { id: node._id } }
          })
          if (node._label === 'users') {
            delete node.is_admin
          }
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
  }

  async findById (user: any, id: string) {
    return this.konekto.findById(id, {
      hooks: {
        beforeRead: (node: any) => beforeRead(user, node, this.rbac)
      }
    })
  }

  async findByQueryObject (user: any, queryObject: any) {
    return this.konekto.findByQueryObject(queryObject, {
      hooks: {
        beforeParseNode (node: any) {
          if (node._where) {
            node._where.filter = `({this}.deleted IS NULL) AND (${node._where})`
          } else {
            node._where = { filter: '{this}.deleted IS NULL' }
          }
        },
        beforeRead: (node: any) => beforeRead(user, node, this.rbac)
      }
    })
  }
}
