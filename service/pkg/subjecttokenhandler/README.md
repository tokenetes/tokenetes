# Subject token handlers

Handlers in this package verify the subject token a caller sends with a TraT
request and return its parsed claims. They do not pick the TraT's `sub` value.
That choice lives in `TokenetesConfig.token.sub`.

## Configuration

```yaml
token:
  issuer:   https://issuer.example.com
  audience: https://audience.example.com
  lifeTime: 5m
  sub: "${subjectToken.email}"   # how the TraT's `sub` is populated

subjectTokens:
  OIDC:
    clientId:    alpha-stocks-client
    providerURL: http://dex:5556/dex
  selfSigned:
    validation:   true
    jwksEndpoint: "http://example.com/.well-known/jwks.json"
```

### The `sub` expression

`token.sub` is either:

- A plain string. The TraT's `sub` becomes that exact string.
- `${subjectToken.<gjsonPath>}`. The path runs against the verified claims of
  whatever subject token the caller used.

So with `sub: "${subjectToken.email}"`:

| Subject token  | Verified claims                                | Resulting TraT `sub` |
|----------------|------------------------------------------------|----------------------|
| OIDC ID token  | `{ "email": "ada@example.com", "sub": "..." }` | `"ada@example.com"`  |
| Self-signed    | `{ "email": "ada@example.com", "sub": "..." }` | `"ada@example.com"`  |

Nested paths work: `${subjectToken.user.id}` reads `claims.user.id`.

If `token.sub` is missing, or the path isn't in the claims, the request gets a
400.

## How each token type is verified

### OIDC

`OIDCTokenHandler` builds a standard `oidc.IDTokenVerifier` from `clientId` and
`providerURL`. It pulls the provider's discovery document at startup with up to
5 retries (exponential backoff). On each request it checks the token's
signature, issuer, audience, and expiry, then hands back the claims as
`jwt.MapClaims`.

### Self-signed

`SelfSignedTokenHandler` looks at `subjectTokens.selfSigned`:

- `validation: true`: fetch JWKS from `jwksEndpoint`, find the key by `kid`,
  verify, return claims.
- `validation: false`: parse without verifying. Dev-only. The handler logs a
  warning because turning this on in prod is a real security hole.

## Why `sub` moved to `token`

The old config split the decision two ways. OIDC had a `subjectField` and only
knew how to format it as an email (anything else got rejected). Self-signed
tokens hardcoded `claims["sub"]`. Neither was discoverable from the YAML, and
OIDC was stuck on email.

Putting the expression on `TokenetesConfig.token.sub` collapses both paths into
one. Same syntax for both token kinds, any claim can drive `sub`, and the
mapping is right next to `issuer` and `audience` where you'd expect it.
