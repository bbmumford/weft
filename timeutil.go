/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"time"
)

// DBTimeLayout is the single canonical SQLite DATETIME format we persist.
// We keep only one format (UTC, no offset) because the database is new/empty
// and we don't need legacy flexible parsing.
// Example: 2006-01-02 15:04:05
const DBTimeLayout = "2006-01-02 15:04:05"

// DBFormat returns a UTC time formatted for storage.
func DBFormat(t time.Time) string { return t.UTC().Format(DBTimeLayout) }

// DBTimeNow is a convenience helper for inline SQL parameters expecting DATETIME.
func DBTimeNow() string { return DBFormat(time.Now()) }

// DBParse converts a stored DATETIME string back to time.Time (UTC).
func DBParse(s string) (time.Time, error) { return time.ParseInLocation(DBTimeLayout, s, time.UTC) }
