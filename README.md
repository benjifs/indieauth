# IndieAuth

For a fully working example, checkout the [serverless-indieauth](https://github.com/benjifs/serverless-indieauth)
repository which provides a basic working example for an IndieAuth server using [Netlify functions](https://docs.netlify.com/build/functions/overview/).

## Install

`npm install @benjifs/indieauth`

## Usage

```js
import { AuthHandler } from '@benjifs/indieauth'
const { SECRET, PASSWORD_SECRET } = process.env
export const indieauth = new AuthHandler({
  secret: SECRET,
  passwordSecret: PASSWORD_SECRET,
})

export default async (req) => indieauth.authorizationEndpoint(req)
```

The following variables are needed in order to create the access tokens and authenticate:

### `SECRET`
A random generated string which will be used to create the access token. You can
generate it with:
- `openssl rand -hex 16`
- Generate a [random string](https://generate-random.org/string-generator)

### `PASSWORD_SECRET`
Your password hashed with [bcrypt](https://en.wikipedia.org/wiki/Bcrypt). To do so
you can either
- `htpasswd -bnBC 10 "" toomanysecrets | cut -d : -f 2`
- Use [this website](https://www.bcrypt.io/) to create the hash

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
