// @ts-nocheck
import Lola from '../../src/index'
import axios, { AxiosInstance } from 'axios'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

jest.mock('konekto', () =>
  jest.fn().mockImplementation(() => ({
    save: jest.fn().mockReturnValue('some_id')
  }))
)
jest.mock('bcrypt')

describe('lola - integration', () => {
  let lola: Lola
  let client: AxiosInstance
  beforeAll(async () => {
    client = axios.create({ baseURL: 'http://localhost:8080' })
    lola = new Lola({ jwtConfig: { secret: 'xd' }, rbacOptions: {} })
    await lola.seed({ graphName: 'lola_integration_test' })
    await lola.start('localhost', 8080)
  })
  beforeEach(() => konekto.deleteByQueryObject({}))
  afterAll(async () => {
    lola.stop()
  })
  describe('SignUp', () => {
    test('Should create new user and return jwt token for authentication', async () => {
      const response = await client.post('/signup', { username: 'user', password: 'pass' })
      expect(bcrypt.hash).toHaveBeenCalledWith('test')
      expect(response.data).toHaveProperty('token')
      expect(jwt.verify(response.data.token, 'xd')._id).toBe(user._id)
    })
    test('Should throw an error when not providing username', async () => {
      try {
        await client.post('/signup', { password: 'test' })
      } catch (error) {
        await expect(error.response.status).toBe(400)
        await expect(error.response.data.message).toBe('username and password are required')
      }
    })
  })

  describe('SignIn', () => {
    test('SignIn - Should return jwt token when providing valid credentials', async () => {
      await client.post('/signup', { username: 'test', password: 'test' })
      const response = await client.post('/signin', { username: 'test', password: 'test' })
      expect(response.data).toHaveProperty('token')
      expect(jwt.verify(response.data.token, 'xd')._id).toBe(user._id)
    })
  })
})
