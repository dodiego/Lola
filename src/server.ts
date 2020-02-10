import server, { HttpResponse } from 'uWebSockets.js'
import bcrypt from 'bcrypt'
import qs from 'qs'
import { onAborted, readBody, respond, TokenHelper, JwtConfig, validate } from './utils'
import Controller from './controller'
import { RBAC } from 'fast-rbac'
interface ServerConfig {
  konekto: any
  jwtConfig: JwtConfig
  rbacOptions: RBAC.Options
  validations?: any
}

async function handleRequest (res: HttpResponse, handler: () => Promise<any>) {
  try {
    await handler()
  } catch (error) {
    respond(res.writeStatus(error.status), { message: error.message })
  }
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
    const controller = new Controller(validations, konekto, rbac)
    app.post('/signup', async (res, _req) => {
      onAborted(res)
      const payload = await readBody(res)
      await handleRequest(res, async () => {
        const _id = await controller.createUser(payload)
        await tokenHelper.getToken(res, _id)
      })
    })

    app.post('/signin', async (res, _req) => {
      onAborted(res)
      const payload = await readBody(res)
      await handleRequest(res, async () => {
        const user = await controller.findUser(payload)
        await tokenHelper.getToken(res, user._id)
      })
    })

    app.get('/me', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      await handleRequest(res, async () => {
        const user = await tokenHelper.authenticate(res, token)
        const me = await controller.findById(user, user._id)
        respond(res, me)
      })
    })

    app.post('/api', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      await handleRequest(res, async () => {
        const body = await readBody(res)
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.save(user, body)
        respond(res, result)
      })
    })

    app.get('/api', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      const query = req.getQuery()
      await handleRequest(res, async () => {
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.findByQueryObject(user, qs.parse(query))
        respond(res, result)
      })
    })

    app.get('/api/id/:id', async (res, req) => {
      onAborted(res)
      const id = req.getParameter(0)
      const token = req.getHeader('authorization')
      await handleRequest(res, async () => {
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.findById(user, id)
        if (result) {
          return respond(res, result)
        }
        return respond(res, { message: 'root not found' })
      })
    })

    app.del('/api', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      const query = req.getQuery()
      await handleRequest(res, async () => {
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.deleteByQueryObject(user, qs.parse(query))
        respond(res, result)
      })
    })

    app.del('/api/id/:id', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      const id = req.getParameter(0)
      await handleRequest(res, async () => {
        const user = await tokenHelper.authenticate(res, token)
        const result = await controller.deleteById(user, id)
        respond(res, result)
      })
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
