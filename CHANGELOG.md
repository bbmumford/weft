# Changelog

## [0.3.0](https://github.com/bbmumford/weft/compare/v0.2.0...v0.3.0) (2026-11-26)


### ⚠ BREAKING CHANGES

* RequireEnvInt and RequireEnvBool are removed.

### Features

* weft no longer exports RequireEnvInt and RequireEnvBool ([f640e0d](https://github.com/bbmumford/weft/commit/f640e0dc7010322d3b696da6c45065a639ecc035))

## [0.2.0](https://github.com/bbmumford/weft/compare/v0.1.0...v0.2.0) (2026-11-25)


### Features

* ParseTrustedEdgePrefixes reads a deployment's declared trusted edge prefixes and refuses a malformed one ([e9ae079](https://github.com/bbmumford/weft/commit/e9ae079028fd547adcd2da57315110defd9a4f53))
* SecurityHeaders gives a path its own CORS policy of exact origins, and ParseCORSOrigin checks one ([fb111b7](https://github.com/bbmumford/weft/commit/fb111b7c76a8c1fbb75bb30e079e89c35d4a809f))


### Bug Fixes

* ClientIPFromRequest returns a forwarded header's value only when it parses as an IP address ([515279a](https://github.com/bbmumford/weft/commit/515279a4589e8e231e39877d02f9a5d156d33713))
* ValidateRedirect refuses a relative target a browser would resolve to another host ([7ee2090](https://github.com/bbmumford/weft/commit/7ee209057a32ca62f23c916a592794c192b4efb2))
