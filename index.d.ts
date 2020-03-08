import RBAC from 'fast-rbac'
import { ConnectionConfig } from 'pg'
import { SignOptions } from 'jsonwebtoken'

export interface LolaConfig {
  jwtConfig: JwtConfig
  rbacOptions: RBAC.Options
  connectionConfig?: ConnectionConfig
  validations?: any
}

export interface JwtConfig {
  options?: SignOptions
  secret: string
}

export interface ServerConfig {
  konekto: any
  jwtConfig: JwtConfig
  rbacOptions: RBAC.Options
  validations?: any
}
