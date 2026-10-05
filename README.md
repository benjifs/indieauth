# IndieAuth

For a fully working example, checkout the [serverless-indieauth](https://github.com/benjifs/serverless-indieauth)
repository which provides a basic working example for an IndieAuth server using [Netlify functions](https://docs.netlify.com/build/functions/overview/).

## Install

`npm install @benjifs/indieauth`

## Usage

```js
import { AuthHandler } from '@benjifs/indieauth'
const { PASSWORD_SECRET, PRIVATE_KEY, PUBLIC_KEY } = process.env
export const indieauth = new AuthHandler({
  passwordSecret: PASSWORD_SECRET,
  privateKey: PRIVATE_KEY,
  publicKey: PUBLIC_KEY,
})

export default async (req) => indieauth.authorizationEndpoint(req)
```

The following variables are needed in order to create the access tokens and authenticate:

### `PASSWORD_SECRET`
Your password hashed with [bcrypt](https://en.wikipedia.org/wiki/Bcrypt). To do so
you can either:
- `htpasswd -bnBC 10 "" toomanysecrets | cut -d : -f 2` where "toomanysecrets" is the password
- Use [this website](https://www.bcrypt.io/) to create the hash

### `PRIVATE_KEY`
You need to create a Public and Private RSA key to sign the tokens. To create a private key:
```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
```
**IMPORTANT**: You should not share or add `private.pem` to your repository.

### `PUBLIC_KEY`
```
openssl pkey -in private.pem -pubout -out public.pem
```

## Supported Scopes
* create - create posts
* update - update existing posts
* delete - delete posts
* media - upload assets to your media endpoint
* profile - share basic profile data
* email - share your email address

## References
* [IndieAuth spec](https://indieauth.spec.indieweb.org/)
* [authorization-endpoint](https://indieweb.org/authorization-endpoint)
* [token-endpoint](https://indieweb.org/token-endpoint)
