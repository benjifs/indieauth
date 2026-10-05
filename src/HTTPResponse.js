const HTTPResponse = (status = 200, body, headers = {}) => {
	if (!headers['Content-Type']) headers['Content-Type'] = 'application/json'
	if (typeof body === 'object' && body !== null) {
		body = 'application/json' === headers['Content-Type'] ? JSON.stringify(body) : new URLSearchParams(body)
	}
	return new Response(body, {
		status,
		headers: {
			...headers,
			// S902
			'X-Frame-Options': 'DENY',
		},
	})
}

export default HTTPResponse
