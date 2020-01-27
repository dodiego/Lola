require('dotenv').config({
  path: require('path').join(__dirname, '..', '.env')
})
const env = require('require-env')
module.exports = {
  hostname: env.require('HOST'),
  port: env.require('PORT'),
  secret: env.require('SECRET'),
  graphName: env.require('GRAPH_NAME'),
  tokenConfig: process.env.NODE_ENV === 'production' ? { expiresIn: '5m' } : {}
}
