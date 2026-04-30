'use strict'

const async = require('async')
const Base = require('@bitfinex/bfx-facs-base')
const FastifyAuth = require('@fastify/oauth2')

const SUPPORTED_AUTHS = ['google', 'microsoft']

class HttpdAuthFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'httpd-oauth2'
    this._hasConf = true

    this.init()
  }

  getSpecs (method) {
    const specs = {}

    switch (method) {
      case 'google':
        specs.name = 'googleOAuth2'
        specs.auth = FastifyAuth.GOOGLE_CONFIGURATION
        specs.startRedirectPath = this.conf.startRedirectPath || '/login/google'
        specs.callbackUri = this.conf.callbackUri || '/login/google/callback'
        specs.callbackUriParams = {
          access_type: 'offline'
        }
        break
      case 'microsoft':
        specs.name = 'microsoftOAuth2'
        specs.auth = FastifyAuth.MICROSOFT_CONFIGURATION
        specs.startRedirectPath = this.conf.startRedirectPath || '/login/microsoft'
        specs.callbackUri = this.conf.callbackUri || '/login/microsoft/callback'
        specs.callbackUriParams = {
          response_mode: 'query'
        }
        break
    }

    return specs
  }

  injection (opts = {}) {
    const creds = this.conf.credentials
    const specs = this.getSpecs(this.conf.method)
    const auth = this.conf.method === 'microsoft'
      ? {
          ...specs.auth,
          authorizePath: `/${creds.tenant}/oauth2/v2.0/authorize`,
          tokenPath: `/${creds.tenant}/oauth2/v2.0/token`
        }
      : specs.auth

    return [FastifyAuth, {
      name: specs.name,
      scope: this.conf.method === 'microsoft' ? ['openid', 'profile', 'email'] : ['profile', 'email'],
      credentials: {
        client: creds.client,
        auth
      },
      startRedirectPath: specs.startRedirectPath,
      callbackUri: specs.callbackUri,
      callbackUriParams: specs.callbackUriParams,
      ...opts
    }]
  }

  resolveUserAccess (user, idField = 'email') {
    return this.conf.users.find(u => u[idField] === user)
  }

  callbackUriUI () {
    return this.conf.callbackUriUI
  }

  _start (cb) {
    async.series([
      next => { super._start(next) },
      async () => {
        if (!SUPPORTED_AUTHS.includes(this.conf.method)) {
          throw new Error('ERR_FACS_HTTPD_OAUTH2_METHOD_INVALID')
        }
      }
    ], cb)
  }
}

module.exports = HttpdAuthFacility
