import StatusError from './statusError.js'
import { normalizeMe, generateJWT, verifyJWT, isValidToken } from './utils.js'
import { getUserInfo } from './parse.js'

const EXPIRATION = 1

export class TokenEndpoint {
	#privateKey
	#publicKey

	constructor({ privateKey, publicKey }) {
		this.#privateKey = privateKey
		this.#publicKey = publicKey
	}

	verifyAccessToken = async (token) => {
		if (!this.#publicKey) throw new StatusError(500, 'Missing "publicKey"')
		if (!token) throw new StatusError(401, 'invalid_token')
		try {
			const data = await verifyJWT(token, this.#publicKey)
			return {
				active: true,
				...data,
			}
		} catch (err) {
			console.error(err && err.message)
			throw new StatusError(200, 'invalid_token')
		}
	}

	redeemAuthorizationCode = async ({ grant_type, code, refresh_token, client_id, redirect_uri, code_verifier }) => {
		if (!this.#privateKey) throw new StatusError(500, 'Missing "privateKey"')
		const token = grant_type === 'authorization_code' ? code : refresh_token
		if (!['authorization_code', 'refresh_token'].includes(grant_type) || !token) throw new StatusError(400, 'invalid_request')
		try {
			const data = await verifyJWT(token, this.#publicKey, grant_type === 'refresh_token' ? 'rt+jwt' : undefined)
			const me = normalizeMe(data.me)
			await isValidToken(data, { client_id, redirect_uri, code_verifier })
			// Only issue `access_token` if there is at least one `scope`
			// https://indieauth.spec.indieweb.org/#access-token-response
			if (!data?.scope) return { me }
			const profile = await getUserInfo(data)
			const access_token = await generateJWT({
				me,
				client_id: data.client_id,
				iss: data.iss,
				scope: data.scope,
			}, this.#privateKey, `${EXPIRATION}d`)
			const refresh_token = await generateJWT({
				me,
				client_id: data.client_id,
				iss: data.iss,
				scope: data.scope,
			}, this.#privateKey, `${EXPIRATION * 10}d`, 'rt+jwt')
			return {
				me,
				access_token,
				refresh_token,
				token_type: 'Bearer',
				scope: data.scope,
				...(profile?.url && { profile }),
				expires_in: EXPIRATION * 24 * 60 * 60,
			}
		} catch (err) {
			throw new StatusError(400, err && err.message)
		}
	}
}
