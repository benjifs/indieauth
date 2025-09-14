import { mf2 } from 'microformats-parser'

const getMFFrom = async (url) => {
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

export const getAppDetails = async (url) => {
	const mf = await getMFFrom(url)
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

const getHCard = async (url) => {
	const mf = await getMFFrom(url)
	const hcard = mf?.items?.find(i => i.type?.includes('h-card'))?.properties
	return !hcard ? null : {
		name: hcard.name?.[0] ?? null,
		photo: hcard.photo?.[0] ?? null,
		url: hcard.url?.[0] ?? null,
		email: hcard.email?.[0] ?? null,
	}
}

export const getUserInfo = async ({ me, scope }) => {
	if (!scope?.includes('profile')) return {}
	const hcard = await getHCard(me)
	return !hcard ? {} : {
		name: hcard.name,
		photo: hcard.photo?.value ?? hcard.photo,
		url: hcard.url,
		...(scope?.includes('email') && hcard.email && { email: hcard.email.replace('mailto:', '') }),
	}
}
