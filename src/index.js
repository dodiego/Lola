const config = require('./config')
const bcrypt = require('bcrypt')
const qs = require('qs')
const { RBAC } = require('fast-rbac')
const fastify = require('fastify')({
  querystringParser: str => qs.parse(str),
  logger: true
})
const Konekto = require('konekto')
const konekto = new Konekto()
const rbac = new RBAC(require('./rbac'))
async function getToken (res, _id, isAdmin) {
  try {
    const token = await fastify.jwt.sign({ _id, is_admin: isAdmin }, config.tokenConfig)
    return { token }
  } catch (error) {
    res.internalServerError("couldn't login, please try again")
  }
}

fastify.register(require('fastify-sensible'))
fastify.register(require('fastify-jwt'), {
  secret: config.secret
})

fastify.decorate('authenticate', async function (request, reply) {
  try {
    const user = await request.jwtVerify()
    const userDb = await konekto.findOneByQueryObject({
      _label: 'users',
      _where: { filter: '{this}._id = :id', params: { id: user._id } }
    })
    if (!userDb) {
      throw new Error("User does't exist")
    }
  } catch (err) {
    fastify.log.error(err)
    reply.unauthorized()
  }
})

fastify.post(
  '/signup',
  {
    schema: {
      body: {
        type: 'object',
        properties: {
          username: { type: 'string' },
          password: { type: 'string' }
        },
        required: ['username', 'password']
      }
    }
  },
  async (req, res) => {
    const saltRounds = 10
    req.body.password = await bcrypt.hash(req.body.password, saltRounds)
    req.body._label = 'users'
    delete req.body.is_admin
    const id = await konekto.save(req.body)
    return getToken(res, id, { is_admin: false })
  }
)

fastify.post(
  '/signin',
  {
    schema: {
      body: {
        type: 'object',
        properties: {
          username: { type: 'string' },
          password: { type: 'string' }
        },
        required: ['username', 'password']
      }
    }
  },
  async (req, res) => {
    const user = await konekto.findOneByQueryObject({
      _label: 'users',
      _where: {
        filter: '{this}.username = :username',
        params: {
          username: req.body.username
        }
      }
    })
    if (!user) {
      return res.notFound('user not found')
    }
    if (!(await bcrypt.compare(req.body.password, user.password))) {
      return res.badRequest('invalid password')
    }
    delete user.password
    return getToken(res, user._id, { is_admin: user.is_admin })
  }
)

fastify.get('/me', { preValidation: [fastify.authenticate] }, (req, res) => {
  return konekto.findById(req.user._id, {
    hooks: {
      beforeRead: node => {
        if (!rbac.can('users', node._label, 'read', { user: req.user, node })) {
          return false
        }
        if (node._label === 'users') {
          delete node.password
        }
        return true
      }
    }
  })
})

fastify.post('/api', { preValidation: [fastify.authenticate] }, (req, res) => {
  try {
    return konekto.save(req.body, {
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
            return rbac.can('users', node._label, 'update', { user: req.user, node })
          }
          if (!rbac.can('users', node._label, 'create', { user: req.user, node })) {
            return false
          }
          if (node._id !== req.user._id) {
            node.user_id = req.user._id
          }
          return true
        }
      }
    })
  } catch (error) {
    fastify.log.error(error)
    res.forbidden('You cannot perform this action')
  }
})

fastify.get('/api', { preValidation: [fastify.authenticate] }, (req, res) => {
  try {
    return konekto.findByQueryObject(req.query, {
      hooks: {
        beforeParseNode (node) {
          if (node._where) {
            node._where.filter = `({this}.deleted IS NULL) AND (${node._where})`
          } else {
            node._where = { filter: '{this}.deleted IS NULL' }
          }
        },
        beforeRead: node => {
          if (!rbac.can('users', node._label, 'read', { user: req.user, node })) {
            return false
          }
          if (node._label === 'users') {
            delete node.password
          }
          return true
        }
      }
    })
  } catch (error) {
    fastify.log.error(error)
    res.internalServerError('Plase try again')
  }
})

fastify.get('/api/id/:id', { preValidation: [fastify.authenticate] }, async (req, res) => {
  try {
    const result = await konekto.findById(req.params.id, {
      hooks: {
        beforeRead: node => {
          if (!rbac.can('users', node._label, 'read', { user: req.user, node })) {
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
      return res.send(result)
    }
    return res.notFound('root not found')
  } catch (error) {
    fastify.log.error(error)
    res.internalServerError('Plase try again')
  }
})

fastify.delete('/api', { preValidation: [fastify.authenticate] }, async (req, res) => {
  const result = await konekto.findByQueryObject(req.query)
  await konekto.save(result, {
    hooks: {
      beforeSave (node) {
        if (!rbac.can('users', node._label, 'delete', { user: req.user, node })) {
          return false
        }
        node.deleted = true
        return true
      }
    }
  })
})

fastify.delete('/api/id/:id', { preValidation: [fastify.authenticate] }, async (req, res) => {
  const result = await konekto.findOneByQueryObject({
    _where: {
      filter: '{this}._id = :id',
      params: {
        id: req.params.id
      }
    }
  })
  return konekto.save(result, {
    hooks: {
      beforeSave (node) {
        if (!rbac.can('users', node._label, 'delete', { user: req.user, node })) {
          return false
        }
        node.deleted = true
        return true
      }
    }
  })
})

fastify.delete('/api/relationships', { preValidation: [fastify.authenticate] }, (req, res) => {
  return konekto.deleteRelationships(req.query)
})

async function run () {
  await konekto.connect()
  await konekto.createGraph(config.graphName)
  await konekto.setGraph(config.graphName)
  await konekto.createSchema(require('./schema'))
  const admin = await konekto.findOneByQueryObject({
    _label: 'users',
    _where: { filter: '{this}.username = :username', params: { username: config.adminUsername } }
  })
  if (!admin) {
    await konekto.save({
      _label: 'users',
      is_admin: true,
      username: config.adminUsername,
      password: await bcrypt.hash(config.adminPassword, 10)
    })
  }
  await fastify.listen(config.port, config.hostname)
}

run().catch(e => {
  fastify.log.fatal(e)
  process.exit(1)
})
