# weft

weft is shared HTTP plumbing for Go services, independent of any router or identity store.

- **Request-context carriers**: who is calling (`SetAuthContext`: subject, scopes, auth type; `WithSessionID`), which partitions the call reaches (`WithPartition`, `WithPartitions`: an opaque axis-to-value map), and the caller's client IP and user agent (`WithClientIP`, `WithUserAgent`), with readers such as `ExtractScopes` and `GetAuthType`.
- **Middleware**: authentication over an `Authenticator` and `Gate`s you supply (`RequireAuth`), session attachment (`AttachSession`), panic recovery (`Recovery`), request logging (`RequestLogging`), security headers, CORS and a canonical-host redirect (`SecurityHeaders`), maintenance mode (`Maintenance`), per-request deadlines (`RequestDeadline`) and a concurrency cap (`NewConcurrencyGuard`).
- **Client IP**: `ClientIPFromRequest` believes forwarding headers only from proxies inside the trusted prefixes you name, and returns a forwarded value only when it parses as an IP address; `ParseTrustedEdgePrefixes` reads a deployment's declared trusted prefixes and refuses a malformed one.
- Small helpers: id and token generation, environment readers, htmx response headers, redirect validation and the database time format.

## Use

```sh
go get github.com/bbmumford/weft
```

```go
auth := weft.RequireAuth(weft.AuthConfig{
	Authenticator: weft.AuthenticatorFunc(func(r *http.Request) (weft.Subject, error) {
		// prove the request's credential
	}),
	Gates: []weft.Gate{ /* extra checks on the proved subject */ },
})

handler = weft.Recovery(reportPanic)(auth(weft.RequestDeadline(30*time.Second)(mux)))

// in a handler:
scopes := weft.ExtractScopes(r.Context())
```

## Dependencies

- No other package of this estate.
- `github.com/google/uuid`, for generated ids.

## Used by

Importers in the ORBTR estate (packages per module):

- `github.com/ORBTR/cortex` (9), `github.com/ORBTR/Library` (6) and
  `github.com/ORBTR/constellation` (6).
- The AI endpoints `api`, `app`, `console`, `fleet`, `manage`, `studio` and
  `worker.orbtr.ai`, and `github.com/ORBTR/xyz`.
- The IO endpoints `app` (2), `devices`, `get`, `help`, `mcp` and
  `relay.orbtr.io`.
- `github.com/bbmumford/loom/node` and `github.com/bbmumford/shuttle`.

## Platforms and build

Pure Go, no cgo and no build tags. The module's `go` directive is 1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
