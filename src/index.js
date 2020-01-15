const config = require('./config')
const qs = require('qs')
const fastify = require('fastify')({
  querystringParser: str => qs.parse(str),
  logger: true
})
const Konekto = require('konekto')
const konekto = new Konekto()

fastify.post('/api', (req, res) => {
  return konekto.save(req.body)
})

fastify.get('/api', (req, res) => {
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

fastify.get('/api/id/:id', (req, res) => {
  return konekto.findById(req.params.id, {
    hooks: {
      beforeRead: node => !node.deleted
    }
  })
})

fastify.delete('/api', async (req, res) => {
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

fastify.delete('/api/id/:id', async (req, res) => {
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

fastify.delete('/api/relationships', (req, res) => {
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
