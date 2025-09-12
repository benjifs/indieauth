import fs from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { mf2 } from 'microformats-parser'
import bcrypt from 'bcryptjs'

import supportedScopes from './scopes.js'
import StatusError from './statusError.js'
import { normalizeMe, encryptToken, decryptToken, isValidToken } from './utils.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

export class AuthEndpoint {
	#secret
	#passwordSecret

	constructor({ secret, passwordSecret }) {
		this.#secret = secret
		this.#passwordSecret = passwordSecret
	}

	#getMFFrom = async (url) => {
		try {
			const res = await fetch(url)
			if (res.headers?.get('content-type').includes('application/json')) {
				return await res.json()
			}
			const html = await res.text()
			return mf2(html, { baseUrl: url })
		} catch (err) {
			console.error('Could not fetch app details', err)
		}
	}

	#getAppDetails = async (url) => {
		const mf = await this.#getMFFrom(url)
		if (!mf) return null
		if (!mf.items && mf.client_id) {
			return {
				name: mf.client_name,
				logo: mf.logo_uri,
				url: mf.client_uri,
			}
		}
		const app = mf?.items?.find(i => i.type?.includes('h-app') || i.type?.includes('h-x-app'))?.properties
		return !app ? null : {
			name: app.name?.[0] ?? null,
			logo: app.logo?.[0] ?? null,
			url: app.url?.[0] ?? null,
		}
	}

	#getHCard = async (url) => {
		const mf = await this.#getMFFrom(url)
		const hcard = mf?.items?.find(i => i.type?.includes('h-card'))?.properties
		return !hcard ? null : {
			name: hcard.name?.[0] ?? null,
			photo: hcard.photo?.[0] ?? null,
			url: hcard.url?.[0] ?? null,
			email: hcard.email?.[0] ?? null,
		}
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
		return new Response(html, {
			status,
			headers: {
				'Content-Type': 'text/html; charset=UTF-8',
			},
		})
	}

	getMetadata = ({ issuer, service_documentation, authorization_endpoint, token_endpoint, introspection_endpoint, userinfo_endpoint }) => {
		const metadata = {
			issuer,
			service_documentation: service_documentation || authorization_endpoint,
			authorization_endpoint,
			token_endpoint,
			introspection_endpoint,
			userinfo_endpoint,
			scopes_supported: Object.keys(supportedScopes),
			code_challenge_methods_supported: [ 'S256' ],
			authorization_response_iss_parameter_supported: true,
		}
		// remove empty values just in case they are not defined in the config
		return Object.fromEntries(Object.entries(metadata).filter(([, v]) => v != null))
	}

	showSetup = (url, error = '') => this.#renderTemplate('setup.html', { url, error })

	showLoginForm = async ({ me, client_id, redirect_uri, scope }, url) => {
		if (!this.#secret) return this.showSetup(url, 'Configuration error: Missing "secret"')
		if (!this.#passwordSecret) return this.showSetup(url, 'Configuration error: Missing "passwordSecret"')
		const app = await this.#getAppDetails(client_id)
		const scopes = this.#parseScopes(scope)
		return this.#renderTemplate('login.html', {
			me: normalizeMe(me),
			redirect_uri,
			client_id,
			app_name: app?.name || client_id,
			app_logo: app?.logo ? `<img src="${app.logo.value || app.logo}" ${app.logo.alt ? `alt="${app.logo.alt}"` : ''} width="24">` : '',
			scopes,
		})
	}

	validateLogin = async ({ password, iss }, { me, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope }) => {
		console.log('validateLogin client_id', client_id)
		const app = await this.#getAppDetails(client_id)
		console.log('validateLogin app', app)
		const scopes = this.#parseScopes(scope)
		console.log('validateLogin scopes', scopes)
		try {
			const isValidPassword = await bcrypt.compare(password, this.#passwordSecret)
			if (!isValidPassword) throw new StatusError(401, 'Invalid Password')
			const code = await encryptToken({
				me: normalizeMe(me),
				client_id,
				redirect_uri,
				iss,
				code_challenge,
				code_challenge_method,
				scope,
			}, this.#secret)
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

	getUserInfo = async ({ me, scope }) => {
		if (!scope?.includes('profile')) return {}
		const hcard = await this.#getHCard(me)
		return !hcard ? {} : {
			name: hcard.name,
			photo: hcard.photo?.value ?? hcard.photo,
			url: hcard.url,
			...(scope?.includes('email') && hcard.email && { email: hcard.email.replace('mailto:', '') }),
		}
	}

	getProfile = async ({ grant_type, code, client_id, redirect_uri, code_verifier }) => {
		if ('authorization_code' != grant_type || !code) throw new StatusError(400, 'invalid_request')
		try {
			console.log('code', code)
			const data = await decryptToken(code, this.#secret)
			console.log('data', data)
			await isValidToken(data, { client_id, redirect_uri, code_verifier })
			console.log('isValid')
			const res = { me: data.me, scope: data.scope }
			const profile = await this.getUserInfo(data)
			console.log('profile', profile)
			if (profile?.name) res.profile = profile
			return res
		} catch (err) {
			throw new StatusError(400, err && err.message)
		}
	}
}
