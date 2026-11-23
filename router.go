/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import "net/http"

// Router is the routing surface a route-registration function needs, expressed
// structurally so it names no router implementation. chi.Router satisfies it as
// written, and so does any router offering the same shape — which is the point:
// a package that registers routes should depend on the shape it uses, not on
// whichever mux the composition root happens to pick.
//
// Take this as a parameter rather than a concrete router, so route packages stay
// independent of the mux and testable against a stub.
type Router interface {
	http.Handler

	// Use appends middleware to the router's middleware stack.
	Use(middlewares ...func(http.Handler) http.Handler)

	// HandleFunc registers a handler function for the given pattern.
	HandleFunc(pattern string, handlerFn http.HandlerFunc)

	// Handle registers an http.Handler for the given pattern.
	Handle(pattern string, handler http.Handler)

	// Mount attaches a sub-handler at the given pattern prefix.
	Mount(pattern string, handler http.Handler)

	Get(pattern string, handlerFn http.HandlerFunc)
	Post(pattern string, handlerFn http.HandlerFunc)
	Put(pattern string, handlerFn http.HandlerFunc)
	Delete(pattern string, handlerFn http.HandlerFunc)
	Patch(pattern string, handlerFn http.HandlerFunc)
}

// RootRouter extends Router with the two fallbacks only the top-level router
// answers; subrouters inherit them from the root, so a subrouter parameter
// should be Router rather than RootRouter.
type RootRouter interface {
	Router

	NotFound(handlerFn http.HandlerFunc)
	MethodNotAllowed(handlerFn http.HandlerFunc)
}

// RouterFactory creates fresh router instances. Pass one to route-setup code
// that needs to build a subrouter, so the setup never names the concrete mux.
type RouterFactory func() RootRouter
