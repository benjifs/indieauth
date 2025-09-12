import { createHash } from 'crypto'
import { EncryptJWT, jwtDecrypt, base64url } from 'jose'

export const normalizeMe = (me = '') => me.replace(/\/+$/, '') + '/'

export const encryptToken = async (payload, secret, expiration = '1m') => {
	const key = new TextEncoder().encode(secret)
	return await new EncryptJWT(payload)
		.setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
		.setIssuedAt()
		.setExpirationTime(expiration)
		.encrypt(key)
}

export const decryptToken = async (token, secret) => {
	const key = new TextEncoder().encode(secret)
	const { payload } = await jwtDecrypt(token, key)
	return payload
}

export const isValidToken = async (token, { client_id, redirect_uri, code_verifier }) => {
	if (!token || token.client_id != client_id || token.redirect_uri != redirect_uri) throw new Error('invalid_request')
	if (token.code_challenge && token.code_challenge_method) {
		const code_challenge = await generateCodeChallenge(token.code_challenge_method, code_verifier)
		if (code_challenge != token.code_challenge) throw new Error('invalid_request')
	}
	return true
}

export const generateCodeChallenge = async (method, verifier) => {
	if (method === 'plain') return verifier
	const hash = createHash('sha256').update(verifier).digest()
	return base64url.encode(hash)
}
