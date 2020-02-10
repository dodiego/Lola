import server from 'uWebSockets.js'
import bcrypt from 'bcrypt'
import qs from 'qs'
import { onAborted, readBody, respond, TokenHelper, JwtConfig, validate } from './utils'
import Controller from './controller'
import { RBAC } from 'fast-rbac'
import Ajv from 'ajv'
import pino from 'pino'
const logger = pino()
interface ServerConfig {
  konekto: any
  jwtConfig: JwtConfig
  rbacOptions: RBAC.Options
  validations?: any
}

export = class Server {
  private app: server.TemplatedApp
  private _socket: any
  public isOnline: boolean = false

  constructor ({ konekto, jwtConfig, rbacOptions, validations }: ServerConfig) {
    let rbac: RBAC
    if (!rbacOptions) {
      throw new Error('You must provide at least an empty object for RBAC')
    }
    if (!Object.keys(rbacOptions).length) {
      rbac = new RBAC({
        roles: {
          '*': { can: ['*'] }
        }
      })
    } else {
      rbac = new RBAC(rbacOptions)
    }

    const app = server.App()
    const tokenHelper = new TokenHelper(jwtConfig, konekto)
    const controller = new Controller(validations, konekto, logger, rbac)
    app.post('/signup', async (res, _req) => {
      onAborted(res)
      const payload = await readBody(res)
      try {
        const _id = await controller.createUser(payload)
        await tokenHelper.getToken(res, _id)
      } catch (error) {
        respond(res.writeStatus(error.status), { message: error.message })
      }
    })

    app.post('/signin', async (res, _req) => {
      onAborted(res)
      const payload = await readBody(res)
      try {
        const user = await controller.findUser(payload)
        await tokenHelper.getToken(res, user._id)
      } catch (error) {
        respond(res.writeStatus(error.status), { message: error.message })
      }
    })

    app.get('/me', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      try {
        const user = await tokenHelper.authenticate(res, token)
        const me = await controller.findById(user, user._id)
        respond(res, me)
      } catch (error) {
        logger.error(error)
        respond(res.writeStatus('500'), { message: 'an error occurred' })
      }
    })

    app.post('/api', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      try {
        const body = await readBody(res)
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.save(user, body)
        respond(res, result)
      } catch (error) {
        logger.error(error)
        respond(res.writeStatus('403'), { message: 'You cannot perform this action' })
      }
    })

    app.get('/api', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      const query = req.getQuery()
      try {
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.findByQueryObject(user, qs.parse(query))
        respond(res, result)
      } catch (error) {
        logger.error(error)
        respond(res.writeStatus('500'), { message: 'an error has occurred, please try again' })
      }
    })

    app.get('/api/id/:id', async (res, req) => {
      onAborted(res)
      const id = req.getParameter(0)
      const token = req.getHeader('authorization')
      try {
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.findById(user, id)
        if (result) {
          return respond(res, result)
        }
        return respond(res, { message: 'root not found' })
      } catch (error) {
        logger.error(error)
        respond(res, { message: 'Plase try again' })
      }
    })

    app.del('/api', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      const query = qs.parse(req.getQuery())
      try {
        const user = await tokenHelper.authenticate(res, token)
        const result = await konekto.findByQueryObject(query, {
          hooks: {
            beforeRead: (node: any) => {
              if (!rbac.can('users', node._label, 'read', { user: user, node })) {
                throw new Error('unauthorized')
              }
              if (node._label === 'users') {
                delete node.password
              }
              return true
            }
          }
        })
        await konekto.save(result, {
          hooks: {
            beforeSave (node: any) {
              if (!rbac.can('users', node._label, 'delete', { user: user, node })) {
                return false
              }
              node.deleted = true
              return true
            }
          }
        })
        respond(res, result)
      } catch (error) {
        logger.error(error)
        respond(res, { message: 'please try again' })
      }
    })

    app.del('/api/id/:id', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      const id = req.getParameter(0)
      try {
        const user = await tokenHelper.authenticate(res, token)
        const result = await konekto.findOneByQueryObject(
          {
            _where: {
              filter: '{this}._id = :id',
              params: {
                id
              }
            }
          },
          {
            hooks: {
              beforeRead: (node: any) => {
                if (!rbac.can('users', node._label, 'read', { user: user, node })) {
                  throw new Error('unauthorized')
                }
                if (node._label === 'users') {
                  delete node.password
                }
                return true
              }
            }
          }
        )
        await konekto.save(result, {
          hooks: {
            beforeSave (node: any) {
              if (!rbac.can('users', node._label, 'delete', { user: user, node })) {
                return false
              }
              node.deleted = true
              return true
            }
          }
        })
        respond(res, result)
      } catch (error) {
        logger.error(error)
        respond(res, { message: 'please try again' })
      }
    })

    this.app = app
  }

  async listen (hostname: string, port: number) {
    if (!hostname || typeof hostname !== 'string') {
      throw new Error('You must provide a hostname and it must be a string')
    }
    if (isNaN(port) || typeof port !== 'number' || port < 0) {
      throw new Error('Port must be a number greather or equal to zero')
    }
    await new Promise((resolve, reject) => {
      this.app.listen(hostname, port, socket => {
        if (socket) {
          this._socket = socket
          this.isOnline = true
          resolve(socket)
        } else {
          reject(new Error('failed to start server'))
        }
      })
    })
  }

  disconnect () {
    server.us_listen_socket_close(this._socket)
  }
}
