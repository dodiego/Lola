const Controller = require('../../src/controller')
const Konekto = require('konekto')

describe('controller', () => {
  describe('constructor', () => {
    test('Must successfully instantiate when providing valid parameters', () => {
      const controller = new Controller(new Konekto(), {
        roles: {
          '*': { can: ['*'] }
        }
      })
      expect(controller).toBeInstanceOf(Controller)
    })
  })
})
