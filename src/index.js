const config = require('./config')
const bcrypt = require('bcrypt')
const qs = require('qs')
const fastify = require('fastify')({
  querystringParser: str => qs.parse(str),
  logger: true
})
const Konekto = require('konekto')
const konekto = new Konekto()

async function getToken (res, _id) {
  try {
    const token = await res.jwtSign({ _id }, config.tokenConfig)
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
    await request.jwtVerify()
  } catch (err) {
    reply.send(err)
  }
})

fastify.post(
  '/signup',
  {
    schema: {
      body: {
        type: 'object',
        properties: {
          email: { type: 'string' },
          password: { type: 'string' },
          phone_number: { type: 'string' }
        },
        required: ['email', 'password']
      }
    }
  },
  async (req, res) => {
    const saltRounds = 10
    req.body.password = await bcrypt.hash(req.body.password, saltRounds)
    req.body._label = 'sigma_user'
    const id = await konekto.save(req.body)
    return getToken(res, id)
  }
)

fastify.post(
  '/signin',
  {
    schema: {
      body: {
        type: 'object',
        properties: {
          email: { type: 'string' },
          password: { type: 'string' }
        },
        required: ['email', 'password']
      }
    }
  },
  async (req, res) => {
    const user = await konekto.findOneByQueryObject({
      _label: 'sigma_user',
      _where: {
        filter: '{this}.email = :email',
        params: {
          email: req.body.email
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
    return getToken(res, user._id)
  }
)

fastify.post('/api', { preValidation: [fastify.authenticate] }, (req, res) => {
  return konekto.save(req.body)
})

fastify.get('/api', { preValidation: [fastify.authenticate] }, (req, res) => {
  return konekto.findByQueryObject(req.query, {
    hooks: {
      beforeParseNode (node) {
        if (node._where) {
          node._where.filter = `({this}.deleted IS NULL) AND (${node._where})`
        } else {
          node._where = { filter: '{this}.deleted IS NULL' }
        }
      }
    }
  })
})

fastify.get('/api/id/:id', { preValidation: [fastify.authenticate] }, (req, res) => {
  return konekto.findById(req.params.id, {
    hooks: {
      beforeRead: node => !node.deleted
    }
  })
})

fastify.delete('/api', { preValidation: [fastify.authenticate] }, async (req, res) => {
  const result = await konekto.findByQueryObject(req.query)
  await konekto.save(result, {
    hooks: {
      beforeSave (node) {
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
  result.deleted = true
  return konekto.save(result)
})

fastify.delete('/api/relationships', { preValidation: [fastify.authenticate] }, (req, res) => {
  return konekto.deleteRelationships(req.query)
})

async function run () {
  await konekto.connect()
  await konekto.createGraph('sigma')
  await konekto.setGraph('sigma')
  await konekto.createSchema({
    _label: 'sigma_user',
    interests: {
      _label: 'interest',
      category: {
        _label: 'category'
      }
    }
  })
  await fastify.listen(config.port, config.hostname)
}

run().catch(e => {
  fastify.log.fatal(e)
  process.exit(1)
})
