package weft

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func waitInFlight(t *testing.T, g *ConcurrencyGuard, want int64) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if g.InFlight() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("InFlight did not reach %d (got %d)", want, g.InFlight())
}

func TestNewConcurrencyGuard_PanicsOnNonPositiveCap(t *testing.T) {
	for _, cap := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("NewConcurrencyGuard(%d) did not panic", cap)
				}
			}()
			NewConcurrencyGuard(cap)
		}()
	}
	// A positive cap must not panic.
	NewConcurrencyGuard(1)
}

func TestConcurrencyGuard_UnderCapPassesThrough(t *testing.T) {
	g := NewConcurrencyGuard(2)
	reached := false
	h := g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("under-cap request: reached=%v code=%d, want true/200", reached, rec.Code)
	}
	if n := g.InFlight(); n != 0 {
		t.Fatalf("slot not released after normal return: InFlight=%d", n)
	}
}

// TestConcurrencyGuard_PanicReleasesSlot reddens if the release is not deferred:
// a handler that panics while holding a slot would consume it permanently.
func TestConcurrencyGuard_PanicReleasesSlot(t *testing.T) {
	g := NewConcurrencyGuard(1)
	panicking := g.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	func() {
		defer func() { _ = recover() }()
		panicking.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	if n := g.InFlight(); n != 0 {
		t.Fatalf("slot not released after panic: InFlight=%d", n)
	}
	// The freed slot must admit a subsequent request.
	rec := httptest.NewRecorder()
	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("post-panic request refused: got %d, want 200", rec.Code)
	}
}

// TestConcurrencyGuard_ConcurrentRequestsContend reddens on a counter that never
// increments (a single-request test cannot tell a working guard from a broken one):
// it fills the whole cap, requires the next request to be refused, releases one
// slot, and requires the next request to be admitted.
func TestConcurrencyGuard_ConcurrentRequestsContend(t *testing.T) {
	g := NewConcurrencyGuard(2)
	entered := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup

	block := func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				entered <- struct{}{}
				<-release
			})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}

	// Fill both slots and wait until both handlers are in-flight.
	block()
	block()
	<-entered
	<-entered

	// A third request must be refused without entering the handler.
	rec := httptest.NewRecorder()
	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("over-cap request entered the handler")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-cap request: got %d, want 503", rec.Code)
	}

	// Release one slot; a new request must now be admitted (it enters the handler).
	release <- struct{}{}
	waitInFlight(t, g, 1)

	admitted := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(admitted)
			<-release
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("request not admitted after a slot was released")
	}

	// Unblock every handler still parked on release.
	close(release)
	wg.Wait()
}
