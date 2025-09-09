import fs from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { mf2 } from 'microformats-parser'
import bcrypt from 'bcryptjs'

import scopeDefinitions from './scopes.js'
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
			const html = await res.text()
			return mf2(html, { baseUrl: url })
		} catch (err) {
			console.error('Could not fetch app details', err)
		}
	}

	#getAppDetails = async (url) => {
		const mf = await this.#getMFFrom(url)
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
			output += `<label>${scope} <input type="checkbox" name="scope" value="${scope}" checked>${scopeDefinitions[scope] || 'unknown scope'}</label>`
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
		const app = await this.#getAppDetails(client_id)
		const scopes = this.#parseScopes(scope)
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

	getProfile = async ({ grant_type, code, client_id, redirect_uri, code_verifier }) => {
		if ('authorization_code' != grant_type || !code) throw new StatusError(400, 'invalid_request')
		try {
			const data = await decryptToken(code, this.#secret)
			await isValidToken(data, { client_id, redirect_uri, code_verifier })
			let res = { me: data.me, scope: data.scope }
			if (data.scope?.includes('profile')) {
				const hcard = await this.#getHCard(data.me)
				if (hcard) {
					res.profile = {
						name: hcard.name,
						photo: hcard.photo?.value ?? hcard.photo,
						url: hcard.url,
					}
					if (data.scope?.includes('email') && hcard.email) {
						res.profile.email = hcard.email.replace('mailto:', '')
					}
				}
			}
			return res
		} catch (err) {
			throw new StatusError(400, err && err.message)
		}
	}
}
