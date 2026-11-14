/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"strconv"
	"time"
)

// DBTimeLayout is the SQLite DATETIME layout DBFormat writes: UTC, no offset.
// Example: 2006-01-02 15:04:05
const DBTimeLayout = "2006-01-02 15:04:05"

// goTimeStringLayout is the layout of time.Time's String method without its monotonic
// clock reading, which a driver hands back for a time value it stored as text.
const goTimeStringLayout = "2006-01-02 15:04:05.999999999 -0700 MST"

// DBFormat returns a UTC time formatted for storage.
func DBFormat(t time.Time) string { return t.UTC().Format(DBTimeLayout) }

// DBTimeNow is a convenience helper for inline SQL parameters expecting DATETIME.
func DBTimeNow() string { return DBFormat(time.Now()) }

// DBParse converts a stored DATETIME string back to time.Time (UTC).
func DBParse(s string) (time.Time, error) { return time.ParseInLocation(DBTimeLayout, s, time.UTC) }

// ParseInstant reads an instant from a database column value as the SQL drivers hand
// it back: a time.Time as it is; a string or []byte holding unix seconds, RFC 3339
// (with or without fractional seconds), time.Time's String form, or DBTimeLayout,
// read as UTC. ok is false for any other value. The forms cannot collide: an integer
// parses under no time layout, and RFC 3339 and DBTimeLayout differ in their
// separator.
func ParseInstant(v any) (t time.Time, ok bool) {
	var text string
	switch x := v.(type) {
	case time.Time:
		return x, true
	case string:
		text = x
	case []byte:
		text = string(x)
	default:
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return time.Unix(n, 0), true
	}
	for _, layout := range []string{time.RFC3339Nano, goTimeStringLayout, DBTimeLayout} {
		if t, err := time.Parse(layout, text); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
