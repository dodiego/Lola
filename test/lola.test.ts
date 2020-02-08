// @ts-nocheck
import Lola from '../src/index'
import Server from '../src/server'
import Konekto from 'konekto'
const jwtConfig = {
  secret: 'xd'
}

jest.mock('../src/server')
jest.mock('konekto')

describe('lola', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })
  describe('constructor', () => {
    test('Should instantiate konekto and server on constructor', () => {
      const lola = new Lola(jwtConfig, {}, 'xd')
      expect(Server).toHaveBeenCalledWith({ konekto: lola.konekto, jwtConfig, rbacOptions: {} })
      expect(Konekto).toHaveBeenCalledWith('xd')
    })
  })
  describe('seed', () => {
    let lola: Lola
    beforeEach(async () => {
      lola = new Lola(jwtConfig, {}, 'xd')
    })
    test('Should throw error if graphName is not a string', async () => {
      await expect(lola.seed(1, { _label: 'nice' })).rejects.toThrow('graphName must be a string')
    })
    test('Should throw error if graphName is an empty string', async () => {
      await expect(lola.seed('', { _label: 'nice' })).rejects.toThrow('graphName must be a string')
    })
    test('Should successfully call seed with the correct parameters', async () => {
      await expect(lola.seed('xd', { _label: 'nice' })).resolves.toBe(undefined)
    })
    test('Should call seedFn passing konekto as first parameter', async () => {
      const seedFn = jest.fn()
      await lola.seed('xd', { _label: 'nice' }, seedFn)
      await expect(seedFn).toBeCalledWith(lola.konekto)
    })
    test('Should set _seeded to true after finishing seed', async () => {
      const seedFn = jest.fn()
      await lola.seed('xd', { _label: 'nice' }, seedFn)
      expect(lola._seeded).toBe(true)
    })
    test('Should set _seeded to true after finishing seed without seed function', async () => {
      await lola.seed('xd', { _label: 'nice' })
      expect(lola._seeded).toBe(true)
    })
  })
  describe('start', () => {
    let lola: Lola
    beforeEach(async () => {
      lola = new Lola(jwtConfig, {}, 'xd')
    })
    test('Should throw error if _seeded is false', async () => {
      await expect(lola.start('hostname', 1337)).rejects.toThrow(
        'You need to seed the database before starting the server'
      )
    })
    test('Should call lola.server.listen with the parameters passed to lola.listen', async () => {
      await lola.seed('xd', { _label: 'hehe' })
      await lola.start('hostname', 1337)
      expect(lola.server.listen).toHaveBeenCalledWith('hostname', 1337)
    })
  })
})
