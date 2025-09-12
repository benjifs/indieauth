import { AuthEndpoint } from './authEndpoint.js'
import { TokenEndpoint } from './tokenEndpoint.js'
import StatusError from './statusError.js'

const HTTPResponse = (status = 200, body, contentType) => {
	if (!contentType) contentType = 'application/json'
	if (typeof body === 'object' && body !== null) {
		body = 'application/json' === contentType ? JSON.stringify(body) : new URLSearchParams(body)
	}
	return new Response(body, {
		status,
		headers: { 'Content-Type': contentType },
	})
}

export class AuthHandler {
	#authEndpoint
	#tokenEndpoint

	constructor(opts) {
		this.#authEndpoint = new AuthEndpoint(opts)
		this.#tokenEndpoint = new TokenEndpoint(opts)
	}

	#getAuthToken = req => req.headers?.get('authorization')?.split(' ')[1].trim()

	#getFormData = async (req) => {
		let form = await req.formData()
		return Object.fromEntries(form)
	}

	#getSearchParams = req => Object.fromEntries(new URL(req.url).searchParams)

	#hasRequiredParams = (params, required = []) => {
		if (!params || typeof params !== 'object') return false
		return required.every(key => Object.prototype.hasOwnProperty.call(params, key))
	}

	authorizationEndpoint = async (req) => {
		try {
			if (!['GET', 'POST'].includes(req.method)) throw new StatusError(405, 'method not allowed')
			const params = this.#getSearchParams(req)
			if ('GET' === req.method) {
				if (this.#hasRequiredParams(params, ['me', 'client_id', 'redirect_uri']))
					return await this.#authEndpoint.showLoginForm(params, process.env.URL)
				return this.#authEndpoint.showSetup(process.env.URL)
			}
			const form = await this.#getFormData(req)
			if (!form.grant_type) return await this.#authEndpoint.validateLogin({ ...form, iss: process.env.URL}, params)
			const body = await this.#authEndpoint.getProfile(form)
			return HTTPResponse(200, body, req.headers?.get('accept'))
		} catch (err) {
			return HTTPResponse(err.statusCode || 500, err.message)
		}
	}

	tokenEndpoint = async (req) => {
		try {
			if (!['GET', 'POST'].includes(req.method)) throw new StatusError(405, 'method not allowed')
			if ('GET' === req.method) {
				const body = await this.#tokenEndpoint.verifyAccessToken(this.#getAuthToken(req))
				return HTTPResponse(200, body, req.headers?.get('accept'))
			}
			const form = await this.#getFormData(req)
			const body = await this.#tokenEndpoint.redeemAuthorizationCode(form)
			return HTTPResponse(200, body, req.headers?.get('accept'))
		} catch (err) {
			if (401 === err?.statusCode) return HTTPResponse(200, { active: false }, req.headers?.get('accept'))
			return HTTPResponse(err.statusCode || 500, err.message)
		}
	}

	introspectionEndpoint = async (req) => {
		try {
			if ('POST' !== req.method) throw new StatusError(405, 'method not allowed')
			const body = await this.#tokenEndpoint.verifyAccessToken(this.#getAuthToken(req))
			return HTTPResponse(200, body, req.headers?.get('accept'))
		} catch (err) {
			if (401 === err?.statusCode) return HTTPResponse(200, { active: false }, req.headers?.get('accept'))
			return HTTPResponse(err.statusCode || 500, err.message)
		}
	}

	userInfoEndpoint = async (req) => {
		try {
			if ('GET' !== req.method) throw new StatusError(405, 'method not allowed')
			const token = await this.#tokenEndpoint.verifyAccessToken(this.#getAuthToken(req))
			if (!token?.scope?.includes('profile')) throw new StatusError(403, 'insufficient_scope')
			const body = await this.#authEndpoint.getUserInfo(token)
			return HTTPResponse(200, body, req.headers?.get('accept'))
		} catch (err) {
			return HTTPResponse(err.statusCode || 500, err.message)
		}
	}

	getMetadata = async (req, opts) => {
		if ('GET' !== req.method) return HTTPResponse(405, 'method not allowed')
		return HTTPResponse(200, this.#authEndpoint.getMetadata(opts))
	}
}
