# weft

Shared HTTP plumbing for Go services, independent of any router or identity store.

- **Request-context carriers**: who is calling (`SetAuthContext`: subject, scopes, auth type; `WithSessionID`), which partitions the call reaches (`WithPartition`, `WithPartitions`: an opaque axis-to-value map), and the caller's client IP and user agent (`WithClientIP`, `WithUserAgent`), with readers such as `ExtractScopes` and `GetAuthType`.
- **Middleware**: authentication over an `Authenticator` and `Gate`s you supply (`RequireAuth`), session attachment (`AttachSession`), panic recovery (`Recovery`), request logging (`RequestLogging`), security headers, CORS and a canonical-host redirect (`SecurityHeaders`), maintenance mode (`Maintenance`), per-request deadlines (`RequestDeadline`) and a concurrency cap (`NewConcurrencyGuard`).
- **Client IP**: `ClientIPFromRequest` believes forwarding headers only from proxies inside the trusted prefixes you name.
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

## Consumers

ai cortex, worker, xyz and most ai endpoints (api, app, worker, studio, node, fleet, console, manage), ORBTR library, io constellation and its app, devices, relay, mcp, help and get endpoints, and the shuttle and loom packages.
