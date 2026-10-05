import { createHash } from 'crypto'
import { SignJWT, jwtVerify, exportJWK, importPKCS8, importSPKI, createRemoteJWKSet, base64url } from 'jose'

const TOKEN_HEADERS = {
	alg: 'RS256',
	typ: 'at+jwt',
	kid: '202610',
}

export const normalizeMe = (me = '') => me.replace(/\/+$/, '') + '/'

const getPrivateKey = async (privateKey) => await importPKCS8(privateKey, TOKEN_HEADERS.alg)
const getPublicKey = async (publicKey) => await importSPKI(publicKey, TOKEN_HEADERS.alg)

export const generateJWT = async (payload, privateKey, expiration = '1m', typ = 'at+jwt') => {
	const key = await getPrivateKey(privateKey)
	return await new SignJWT(payload)
		.setProtectedHeader({ ...TOKEN_HEADERS, typ })
		.setSubject(payload.me)
		.setAudience(payload.client_id)
		.setIssuedAt()
		.setExpirationTime(expiration)
		.sign(key)
}

const JWKS = createRemoteJWKSet(new URL(`${process.env.URL}/jwks`))

// Should this just use `getPublicKey` or is it ok to use JWKS for now?
export const verifyJWT = async (token, publicKey, typ = 'at+jwt') => {
	const { payload, protectedHeader } = await jwtVerify(token, JWKS, {
		algorithms: [TOKEN_HEADERS.alg],
	})
	if (protectedHeader.typ !== typ) throw new Error('Invalid token type')
	return payload
}

export const generateJWKS = async (publicKey) => {
	const key = await getPublicKey(publicKey)
	const jwk = await exportJWK(key)
	return {
		keys: [{
			...jwk,
			alg: TOKEN_HEADERS.alg,
			kid: TOKEN_HEADERS.kid,
			use: 'sig',
		}],
	}
}

export const isValidToken = async (token, { client_id, redirect_uri, code_verifier }) => {
	if (!token || token.client_id != client_id || token.redirect_uri != redirect_uri) throw new Error('invalid_request')
	if (token.code_challenge && token.code_challenge_method) {
		const code_challenge = await generateCodeChallenge(token.code_challenge_method, code_verifier)
		if (code_challenge != token.code_challenge) throw new Error('invalid_grant')
	}
	return true
}

export const generateCodeChallenge = async (method, verifier) => {
	if (method === 'plain') return verifier
	const hash = createHash('sha256').update(verifier).digest()
	return base64url.encode(hash)
}
