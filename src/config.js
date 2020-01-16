require('dotenv').config({
  path: require('path').join(__dirname, '..', '.env')
})
const env = require('require-env')
module.exports = {
  hostname: env.require('HOST'),
  port: env.require('PORT'),
  secret: env.require('SECRET'),
  tokenConfig: { expiresIn: '5m' }
}
