const config = require('./config')
const bcrypt = require('bcrypt')
const qs = require('qs')
const { RBAC } = require('fast-rbac')
const server = require('uWebSockets.js')
const logger = require('pino')()
const Konekto = require('konekto')
const konekto = new Konekto()
const rbac = new RBAC(require('./rbac'))
const jwt = require('jsonwebtoken')

/**
 *
 * @param {import('uWebSockets.js').HttpResponse} res
 * @param {String} _id
 */
async function getToken (res, _id) {
  let response
  try {
    const token = await jwt.sign({ _id }, config.secret, config.tokenConfig)
    response = { token }
  } catch (error) {
    response = { message: "couldn't login, please try again" }
    res.writeStatus('500')
  }
  respond(res, JSON.stringify(response))
}

function onAborted (res) {
  res.onAborted(() => {
    res.aborted = true
  })
}

function respond (res, result) {
  if (!res.aborted) {
    res.end(JSON.stringify(result))
  }
}

/**
 *
 * @param {import('uWebSockets.js').HttpResponse} res
 */
function readBody (res) {
  let buffer
  return new Promise((resolve, reject) => {
    res.onData((ab, isLast) => {
      const chunk = Buffer.from(ab)
      if (isLast) {
        let json
        if (buffer) {
          try {
            json = JSON.parse(Buffer.concat([buffer, chunk]))
          } catch (e) {
            res.close()
            reject(e)
          }

          resolve(json)
        } else {
          try {
            json = JSON.parse(chunk)
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

/**
 *
 * @param {import('uWebSockets.js').HttpResponse} res
 * @param {import('uWebSockets.js').HttpRequest} req
 */
async function getUserFromToken (token) {
  const { _id } = await jwt.verify(token, config.secret)
  const user = await konekto.findOneByQueryObject({
    _label: 'users',
    _where: { filter: '{this}._id = :_id', params: { _id } }
  })
  if (!user) {
    throw new Error("User does't exist")
  }
  return user
}

/**
 *
 * @param {import('uWebSockets.js').HttpResponse} res
 * @param {import('uWebSockets.js').HttpRequest} req
 */
async function authenticate (res, token) {
  try {
    return await getUserFromToken(token)
  } catch (error) {
    logger.error(error)
    respond(res.writeStatus('401'))
    throw error
  }
}

function beforeRead (user, node) {
  if (!rbac.can('users', node._label, 'read', { user, node })) {
    return false
  }
  if (node._label === 'users') {
    delete node.password
  }
  return true
}

function beforeReadDelete (user, node) {
  if (!beforeRead(user, node)) {
    throw new Error('not authorized')
  }
  return true
}

const app = server.App()

app.post('/signup', async (res, req) => {
  onAborted(res)

  const user = await readBody(res)
  const saltRounds = 10
  user.password = await bcrypt.hash(user.password, saltRounds)
  user._label = 'users'
  const id = await konekto.save(user)
  await getToken(res, id)
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
    logger.info('user not found')
    return respond(res.writeStatus('400'))
  }
  if (!(await bcrypt.compare(payload.password, user.password))) {
    logger.info('invalid password')
    return respond(res.writeStatus('400'))
  }
  delete user.password
  await getToken(res, user._id)
})

app.get('/me', async (res, req) => {
  onAborted(res)
  const token = req.getHeader('authorization')
  try {
    const user = await authenticate(res, token)
    const me = await konekto.findById(user._id, {
      hooks: {
        beforeRead: node => beforeRead(user, node)
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
    const user = await authenticate(res, token)
    const result = await konekto.save(body, {
      hooks: {
        beforeSave: async node => {
          const nodeDb = await konekto.findOneByQueryObject({
            _label: node._label,
            _where: { filter: '{this}._id = :id', params: { id: node._id } }
          })
          if (nodeDb) {
            return rbac.can('users', node._label, 'update', { user, node })
          }
          return rbac.can('users', node._label, 'create', { user, node })
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
    const user = await authenticate(res, token)
    const result = await konekto.findByQueryObject(qs.parse(query), {
      hooks: {
        beforeRead: node => beforeRead(user, node)
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
    const user = await authenticate(res, token)
    const result = await konekto.findById(req.params.id, {
      hooks: {
        beforeRead: node => beforeRead(user, node)
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
  const query = qs.parse(req.getQuery())
  try {
    const user = await authenticate(res, token)
    const result = await konekto.findByQueryObject(query, {
      hooks: {
        beforeRead: node =>
          beforeReadDelete(user, node) && rbac.can('users', node._label, 'delete', { user: user, node })
      }
    })
    await konekto.deleteByQueryObject(query)
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
    const user = await authenticate(res, token)
    const result = await konekto.deleteById(id, {
      hooks: {
        beforeRead: node =>
          beforeReadDelete(user, node) && rbac.can('users', node._label, 'delete', { user: user, node })
      }
    })
    respond(res, result)
  } catch (error) {
    logger.error(error)
    respond(res, { message: 'please try again' })
  }
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
  await new Promise((resolve, reject) => {
    app.listen(config.hostname, config.port, socket => {
      if (socket) {
        resolve()
      } else {
        reject(new Error('failed to start server'))
      }
    })
  })
  logger.info('server started')
}

run().catch(e => {
  logger.fatal(e)
  process.exit(1)
})

module.exports = class Lola {}
