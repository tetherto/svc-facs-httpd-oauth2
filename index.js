'use strict'

const async = require('async')
const Base = require('bfx-facs-base')
const FastifyAuth = require('@fastify/oauth2')

const SUPPORTED_AUTHS = ['google']

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
    }

    return specs
  }

  injection (opts = {}) {
    const creds = this.conf.credentials
    const specs = this.getSpecs(this.conf.method)

    return [FastifyAuth, {
      name: specs.name,
      scope: ['profile', 'email'],
      credentials: {
        client: creds.client,
        auth: specs.auth
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
