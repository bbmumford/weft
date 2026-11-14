package weft

import (
	"testing"
	"time"
)

func TestParseInstantReadsEveryStoredForm(t *testing.T) {
	want := time.Date(2026, 11, 14, 9, 30, 15, 0, time.UTC)
	frac := time.Date(2026, 11, 14, 9, 30, 15, 123456789, time.UTC)
	for _, c := range []struct {
		name string
		in   any
		want time.Time
	}{
		{"time value", want, want},
		{"unix seconds", "1794648615", want},
		{"unix seconds as bytes", []byte("1794648615"), want},
		{"RFC 3339", "2026-11-14T09:30:15Z", want},
		{"RFC 3339 with an offset", "2026-11-14T20:30:15+11:00", want},
		{"RFC 3339 with fractional seconds", "2026-11-14T09:30:15.123456789Z", frac},
		{"RFC 3339 as bytes", []byte("2026-11-14T09:30:15Z"), want},
		{"time String form", "2026-11-14 09:30:15.123456789 +0000 UTC", frac},
		{"SQLite layout", "2026-11-14 09:30:15", want},
		{"SQLite layout as bytes", []byte("2026-11-14 09:30:15"), want},
	} {
		got, ok := ParseInstant(c.in)
		if !ok || !got.Equal(c.want) {
			t.Errorf("%s: got %v ok=%v, want %v", c.name, got, ok, c.want)
		}
	}
	if got, ok := ParseInstant("2026-11-14 09:30:15"); !ok || got.Location() != time.UTC {
		t.Errorf("the SQLite layout reads as UTC: got %v", got)
	}
}

func TestParseInstantRefusesWhatItCannotRead(t *testing.T) {
	for _, in := range []any{nil, 42, "", "yesterday", []byte("14/11/2026"), 3.5} {
		if got, ok := ParseInstant(in); ok || !got.IsZero() {
			t.Errorf("%#v: got %v ok=%v, want the zero time and false", in, got, ok)
		}
	}
}
