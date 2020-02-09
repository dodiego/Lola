// @ts-nocheck
import Lola from '../../src/index'
import axios, { AxiosInstance } from 'axios'
import Konekto from 'konekto'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
describe('lola - integration', () => {
  let lola: Lola
  let client: AxiosInstance
  const konekto = new Konekto()
  beforeAll(async () => {
    client = axios.create({ baseURL: 'http://localhost:8080' })
    lola = new Lola({ jwtConfig: { secret: 'xd' }, rbacOptions: {} })
    await lola.seed({ graphName: 'lola_integration_test' })
    await lola.start('localhost', 8080)
    await konekto.connect()
    await konekto.setGraph('lola_integration_test')
  })
  beforeEach(() => konekto.deleteByQueryObject({}))
  afterAll(async () => {
    await konekto.disconnect()
    lola.stop()
  })

  test('Should create new user and return jwt token for authentication', async () => {
    const response = await client.post('/signup', { username: 'test', password: 'test' })
    const result = await konekto.findByQueryObject({})
    const user = result[0]
    expect(result.length).toBe(1)
    expect(user).toHaveProperty('_label', 'users')
    expect(user).toHaveProperty('username', 'test')
    expect(await bcrypt.compare('test', user.password)).toBe(true)
    expect(response.data).toHaveProperty('token')
    expect(jwt.verify(response.data.token, 'xd')._id).toBe(user._id)
  })
})
