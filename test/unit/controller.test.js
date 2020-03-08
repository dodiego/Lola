const Controller = require('../../src/controller')
const Konekto = require('konekto')
const { RBAC } = require('fast-rbac')
jest.mock('fast-rbac', () => ({
  RBAC: jest.fn().mockImplementation()
}))

describe('controller', () => {
  beforeEach(() => jest.clearAllMocks())
  describe('constructor', () => {
    test('Must successfully instantiate when providing valid parameters', () => {
      const controller = new Controller(new Konekto(), {})
      expect(controller).toBeInstanceOf(Controller)
    })
    test('Should fail if konekto is not provided as first parameter', () => {
      expect(() => new Controller()).toThrow('You must provide a konekto instance as first parameter')
    })
    test('Should fail does not provide rbac as second paramater', () => {
      expect(() => new Controller(new Konekto())).toThrow('You must provide at least an empty object for RBAC')
    })
    test('Should create a generic rbac rule if empty object is passed as second parameter', () => {
      const controller = new Controller(new Konekto(), {})
      expect(RBAC).toHaveBeenCalledWith({
        roles: {
          '*': { can: ['*'] }
        }
      })
      expect(controller).toBeTruthy()
    })
  })
  describe('createUser', () => {})
})
