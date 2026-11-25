package weft

import (
	"net/http"
	"testing"
)

// stubRouter is the minimum a route package needs to be testable without a mux.
// Its existence is half the point of Router being an interface.
type stubRouter struct {
	http.Handler
	gets []string
	used int
}

func (s *stubRouter) Use(m ...func(http.Handler) http.Handler) { s.used += len(m) }
func (s *stubRouter) HandleFunc(string, http.HandlerFunc)      {}
func (s *stubRouter) Handle(string, http.Handler)              {}
func (s *stubRouter) Mount(string, http.Handler)               {}
func (s *stubRouter) Get(p string, _ http.HandlerFunc)         { s.gets = append(s.gets, p) }
func (s *stubRouter) Post(string, http.HandlerFunc)            {}
func (s *stubRouter) Put(string, http.HandlerFunc)             {}
func (s *stubRouter) Delete(string, http.HandlerFunc)          {}
func (s *stubRouter) Patch(string, http.HandlerFunc)           {}
func (s *stubRouter) NotFound(http.HandlerFunc)                {}
func (s *stubRouter) MethodNotAllowed(http.HandlerFunc)        {}

// A stub satisfying the shape must satisfy both interfaces, or route packages
// cannot be tested against anything but a real mux.
func TestStubSatisfiesRouterAndRootRouter(t *testing.T) {
	s := &stubRouter{}
	var r Router = s
	var root RootRouter = s
	r.Get("/through-router", nil)
	root.Get("/through-root", nil)
	if len(s.gets) != 2 || s.gets[0] != "/through-router" || s.gets[1] != "/through-root" {
		t.Fatalf("the stub recorded %q through its two interfaces, want both routes in order", s.gets)
	}
}

// A RootRouter is usable wherever a Router is wanted — subrouter parameters take
// the narrower Router, and the root must still be passable to them.
func TestRootRouterIsARouter(t *testing.T) {
	var root RootRouter = &stubRouter{}
	register := func(r Router) { r.Get("/healthz", nil) }
	register(root)
	if got := root.(*stubRouter).gets; len(got) != 1 || got[0] != "/healthz" {
		t.Errorf("registration through the narrower interface did not reach the root: %v", got)
	}
}

func TestRouterFactoryReturnsARootRouter(t *testing.T) {
	var f RouterFactory = func() RootRouter { return &stubRouter{} }
	if f() == nil {
		t.Error("factory returned nil")
	}
}
