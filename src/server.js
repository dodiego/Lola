const server = require('uWebSockets.js')
const bcrypt = require('bcrypt')
const qs = require('qs')
const { onAborted, readBody, respond, TokenHelper } = require('./utils')

module.exports = class Server {
  constructor ({ konekto, jwtConfig, rbac }) {
    const app = server.App()
    const tokenHelper = new TokenHelper(jwtConfig)
    const logger = require('pino')()
    app.post('/signup', async (res, req) => {
      onAborted(res)

      const user = await readBody(res)
      const saltRounds = 10
      user.password = await bcrypt.hash(user.password, saltRounds)
      user._label = 'users'
      delete user.is_admin
      const id = await konekto.save(user)
      await tokenHelper.getToken(res, id)
    })

    app.post('/signin', async (res, req) => {
      onAborted(res)
      const payload = await readBody(res)
      const user = await konekto.findOneByQueryObject({
        _label: 'users',
        _where: {
          filter: '{this}.username = :username',
          params: {
            username: payload.username
          }
        }
      })
      if (!user) {
        return respond(res.writeStatus('404'))
      }
      if (!(await bcrypt.compare(payload.password, user.password))) {
        return respond(res.writeStatus('400'))
      }
      delete user.password
      await tokenHelper.getToken(res, user._id)
    })

    app.get('/me', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      try {
        const user = await tokenHelper.authenticate(res, token)
        const me = await konekto.findById(user._id, {
          hooks: {
            beforeRead: node => {
              if (!rbac.can('users', node._label, 'read', { user, node })) {
                return false
              }
              if (node._label === 'users') {
                delete node.password
              }
              return true
            }
          }
        })
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
        const result = await konekto.save(body, {
          hooks: {
            beforeSave: async node => {
              const nodeDb = await konekto.findOneByQueryObject({
                _label: node._label,
                _where: { filter: '{this}._id = :id', params: { id: node._id } }
              })
              if (node._label === 'users') {
                delete node.is_admin
              }
              if (nodeDb) {
                return rbac.can('users', node._label, 'update', { user, node })
              }
              if (!rbac.can('users', node._label, 'create', { user, node })) {
                return false
              }
              if (node._id !== user._id) {
                node.user_id = user._id
              }
              return true
            }
          }
        })
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
        const result = await konekto.findByQueryObject(qs.parse(query), {
          hooks: {
            beforeParseNode (node) {
              if (node._where) {
                node._where.filter = `({this}.deleted IS NULL) AND (${node._where})`
              } else {
                node._where = { filter: '{this}.deleted IS NULL' }
              }
            },
            beforeRead: node => {
              if (!rbac.can('users', node._label, 'read', { user: user, node })) {
                return false
              }
              if (node._label === 'users') {
                delete node.password
              }
              return true
            }
          }
        })
        respond(res, result)
      } catch (error) {
        logger.error(error)
        respond(res.writeStatus('500'), { message: 'an error has occurred, please try again' })
      }
    })

    app.get('/api/id/:id', async (res, req) => {
      onAborted(res)
      const token = req.getHeader('authorization')
      try {
        const user = await tokenHelper.authenticate(res, token)
        const result = await konekto.findById(req.params.id, {
          hooks: {
            beforeRead: node => {
              if (!rbac.can('users', node._label, 'read', { user: user, node })) {
                return false
              }
              if (node._label === 'users') {
                delete node.password
              }
              return true
            }
          }
        })
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
      try {
        const user = await tokenHelper.authenticate(res, token)
        const result = await konekto.findByQueryObject(req.query, {
          hooks: {
            beforeRead: node => {
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
            beforeSave (node) {
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
              beforeRead: node => {
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
            beforeSave (node) {
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
    this.konekto = konekto
    this.logger = logger
  }

  async listen (hostname, port) {
    await new Promise((resolve, reject) => {
      this.app.listen(hostname, port, socket => {
        if (socket) {
          resolve()
        } else {
          reject(new Error('failed to start server'))
        }
      })
    })
    this.logger.info('server started')
  }
}
