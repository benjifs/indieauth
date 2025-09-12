import StatusError from './statusError.js'
import { normalizeMe, encryptToken, decryptToken, isValidToken } from './utils.js'

const EXPIRATION = 90

export class TokenEndpoint {
	#secret

	constructor({ secret }) {
		this.#secret = secret
	}

	verifyAccessToken = async (token) => {
		if (!this.#secret) throw new StatusError(500, 'Missing "secret"')
		if (!token) throw new StatusError(401, 'invalid_token')
		try {
			const data = await decryptToken(token, this.#secret)
			return {
				active: true,
				...data,
			}
		} catch (err) {
			console.error(err && err.message)
			throw new StatusError(401, 'invalid_token')
		}
	}

	redeemAuthorizationCode = async ({ grant_type, code, client_id, redirect_uri, code_verifier }) => {
		if (!this.#secret) throw new StatusError(500, 'Missing "secret"')
		if ('authorization_code' != grant_type || !code) throw new StatusError(400, 'invalid_request')
		try {
			const data = await decryptToken(code, this.#secret)
			// Only check if it has a valid scope when redeeming authorization code
			// https://indieauth.spec.indieweb.org/#access-token-response
			if (!data?.scope) throw new Error('invalid_request')
			await isValidToken(data, { client_id, redirect_uri, code_verifier })
			const access_token = await encryptToken({
				me: normalizeMe(data.me),
				client_id: data.client_id,
				iss: data.iss,
				scope: data.scope,
			}, this.#secret, `${EXPIRATION}d`)
			return {
				access_token,
				token_type: 'Bearer',
				scope: data.scope,
				me: normalizeMe(data.me),
				expires_in: EXPIRATION * 24 * 60 * 60,
			}
		} catch (err) {
			throw new StatusError(400, err && err.message)
		}
	}
}