/// <reference types="@fastify/secure-session" />
import { FastifyRequest } from 'fastify'
import { SerializeFunction } from '../Authenticator'

/** Class for storing passport data in the session using `@fastify/secure-session` or `@fastify/session` */
export class SecureSessionManager {
  key: string
  serializeUser: SerializeFunction

  constructor(options: SerializeFunction | any, serializeUser?: SerializeFunction) {
    if (typeof options === 'function') {
      serializeUser = options
      options = undefined
    }
    options = options || {}

    this.key = options.key || 'passport'
    this.serializeUser = serializeUser!
  }

  async logIn(request: FastifyRequest, user: any) {
    const object = await this.serializeUser(user, request)
    // Handle sessions using @fastify/session
    if (request.session.regenerate) {
      // regenerate session to guard against session fixation
      await request.session.regenerate()
    }
    request.session.set(this.key, object)
  }

  async logOut(request: FastifyRequest) {
    request.session.set(this.key, undefined)
    if (request.session.regenerate) {
      await request.session.regenerate()
    }
  }

  getUserFromSession(request: FastifyRequest) {
    return request.session.get(this.key)
  }
}
