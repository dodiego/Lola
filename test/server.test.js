const Server = require('../src/server')
const Konekto = require('konekto')
const konekto = new Konekto()
const jwtConfig = {
  secret: 'xd'
}
describe('server', () => {
  describe('constructor', () => {
    test('Should instantiate with correct parameters', () => {
      expect(() => new Server({ konekto, jwtConfig, rbac: {} })).not.toThrow()
    })
    test('Should throw if konekto is not provided', () => {
      expect(() => new Server({ jwtConfig, rbac: {} })).toThrow('You must provide a valid Konekto instance')
    })
    test('Should throw if jwtConfig is not provided', () => {
      expect(() => new Server({ konekto, rbac: {} })).toThrow('You must provide jwtConfig')
    })
    test('Should throw if rbac is not provided', () => {
      expect(() => new Server({ konekto, jwtConfig })).toThrow('You must provide at least an empty object for RBAC')
    })
    test('Should throw if jwtConfig.secret is empty', () => {
      expect(() => new Server({ konekto, jwtConfig: { secret: '' }, rbac: {} })).toThrow(
        'jwtConfig.secret must be a non-empty string'
      )
    })
    test('Should throw if jwtConfig.secret is null', () => {
      expect(() => new Server({ konekto, jwtConfig: { secret: null }, rbac: {} })).toThrow(
        'jwtConfig.secret must be a non-empty string'
      )
    })
    test('Should throw if jwtConfig.secret is undefined', () => {
      expect(() => new Server({ konekto, jwtConfig: { secret: undefined }, rbac: {} })).toThrow(
        'jwtConfig.secret is required'
      )
    })
    test('Should throw if jwtConfig is empty object', () => {
      expect(() => new Server({ konekto, jwtConfig: { secret: undefined }, rbac: {} })).toThrow(
        'jwtConfig.secret is required'
      )
    })
  })
  describe('listen', () => {
    let server
    beforeEach(() => {
      server = new Server({ konekto, jwtConfig, rbac: {} })
    })
    afterEach(async () => {
      if (server.isOnline) {
        await server.disconnect()
      }
    })
    test('Should start server when providing hostname and port', async () => {
      await expect(server.listen('localhost', 8080)).resolves.toBe(undefined)
    })
    test('Should start server on a random port when port is zero', async () => {
      await expect(server.listen('localhost', 0)).resolves.toBe(undefined)
    })
    test('Should throw error when not providing hostname', async () => {
      await expect(server.listen()).rejects.toThrow('You must provide a hostname and it must be a string')
    })
    test('Should throw error when hostname is not string', async () => {
      await expect(server.listen(8080)).rejects.toThrow('You must provide a hostname and it must be a string')
    })
    test('Should throw error when hostname is empty string ', async () => {
      await expect(server.listen('')).rejects.toThrow('You must provide a hostname and it must be a string')
    })
    test('Should throw error when not providing port ', async () => {
      await expect(server.listen('localhost')).rejects.toThrow('Port must be a number greather or equal to zero')
    })
    test('Should throw error when port is a negative number', async () => {
      await expect(server.listen('localhost', -1)).rejects.toThrow('Port must be a number greather or equal to zero')
    })
    test('Should throw error when port is NaN', async () => {
      await expect(server.listen('localhost', NaN)).rejects.toThrow('Port must be a number greather or equal to zero')
    })
    test('Should throw error when port is not of type number', async () => {
      await expect(server.listen('localhost', '1')).rejects.toThrow('Port must be a number greather or equal to zero')
    })
  })
})
