import fs from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import bcrypt from 'bcryptjs'

import supportedScopes from './scopes.js'
import StatusError from './statusError.js'
import HTTPResponse from './HTTPResponse.js'
import { normalizeMe, generateJWT, verifyJWT, isValidToken, generateJWKS } from './utils.js'
import { getAppDetails, getUserInfo } from './parse.js'

// const __dirname = dirname(fileURLToPath(import.meta.url))

export class AuthEndpoint {
	#passwordSecret
	#privateKey
	#publicKey

	constructor({ passwordSecret, privateKey, publicKey }) {
		this.#passwordSecret = passwordSecret
		this.#privateKey = privateKey
		this.#publicKey = publicKey
	}

	#parseScopes = scopes => {
		if (!scopes) return []
		return Array.isArray(scopes) ? scopes : scopes.split(' ')
	}

	#renderScopes = (scopes = []) => {
		let output = ''
		for (const scope of scopes) {
			output += `<label>${scope} <input type="checkbox" name="scope" value="${scope}" checked>${supportedScopes[scope] || 'unknown scope'}</label>`
		}
		return output || '<small class="warn">No scopes provided</small>'
	}

	#renderTemplate = async (template, tokens = {}, status = 200) => {
		const filePath = join(__dirname, '../src/html', template)
		let html = await fs.readFile(filePath, { encoding: 'utf-8' })
		html = html.replace('{{scopes}}', this.#renderScopes(tokens.scopes))
		html = html.replace(/{{(\w+)}}/g, (_, key) => tokens[key] ?? '')
		return HTTPResponse(status, html, { 'Content-Type': 'text/html; charset=UTF-8' })
	}

	getMetadata = (values) => {
		const metadata = {
			...values,
			service_documentation: values.service_documentation || values.authorization_endpoint,
			scopes_supported: Object.keys(supportedScopes),
			code_challenge_methods_supported: [ 'S256' ],
			authorization_response_iss_parameter_supported: true,
		}
		// remove empty values just in case they are not defined in the config
		return Object.fromEntries(Object.entries(metadata).filter(([, v]) => v != null))
	}

	showSetup = (url, error = '') => this.#renderTemplate('setup.html', { url, error })

	showLoginForm = async ({ me, client_id, redirect_uri, scope, state, issuer }, url) => {
		if (!this.#passwordSecret) return this.showSetup(url, 'Configuration error: Missing "passwordSecret"')
		if (!this.#privateKey) return this.showSetup(url, 'Configuration error: Missing "privateKey"')
		if (!this.#publicKey) return this.showSetup(url, 'Configuration error: Missing "#publicKey"')
		const app = await getAppDetails(client_id)
		const scopes = this.#parseScopes(scope)
		return this.#renderTemplate('login.html', {
			me: normalizeMe(me),
			redirect_uri,
			client_id,
			app_name: app?.name || client_id,
			app_url: client_id,
			app_logo: app?.logo ? `<img src="${app.logo.value || app.logo}" ${app.logo.alt ? `alt="${app.logo.alt}"` : ''} width="24">` : '',
			scopes,
			state,
			url,
		})
	}

	validateLogin = async ({ password, iss }, { me, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope }) => {
		const app = await getAppDetails(client_id)
		const scopes = this.#parseScopes(scope)
		try {
			const isValidPassword = await bcrypt.compare(password, this.#passwordSecret)
			if (!isValidPassword) throw new StatusError(401, 'Invalid Password')
			const code = await generateJWT({
				me: normalizeMe(me),
				client_id,
				redirect_uri,
				iss,
				code_challenge,
				code_challenge_method,
				scope,
			}, this.#privateKey)
			return new Response('success', {
				status: 302,
				headers: {
					'Location': `${redirect_uri}?code=${code}&iss=${iss}${state ? `&state=${state}` : ''}`,
				},
			})
		} catch (err) {
			console.error(err && err.message)
			return this.#renderTemplate('login.html', {
				error: err.message,
				me: normalizeMe(me),
				redirect_uri,
				client_id,
				app_name: app?.name || client_id,
				app_logo: app?.logo ? `<img src="${app.logo.value || app.logo}" ${app.logo.alt ? `alt="${app.logo.alt}"` : ''} width="24">` : '',
				scopes,
			}, err.statusCode || 500)
		}
	}

	getUserInfo = getUserInfo

	getProfile = async ({ grant_type, code, client_id, redirect_uri, code_verifier }) => {
		if (!grant_type) throw new StatusError(400, 'invalid_request')
		if ('authorization_code' != grant_type) throw new StatusError(400, 'unsupported_grant_type')
		if (!code) throw new StatusError(400, 'invalid_request')
		try {
			const data = await verifyJWT(code, this.#publicKey)
			await isValidToken(data, { client_id, redirect_uri, code_verifier })
			const res = { me: data.me, scope: data.scope }
			const profile = await getUserInfo(data)
			if (profile?.name) res.profile = profile
			return res
		} catch (err) {
			throw new StatusError(400, err && err.message)
		}
	}

	generateJWKS = () => generateJWKS(this.#publicKey)
}
