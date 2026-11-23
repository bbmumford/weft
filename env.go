/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"log"
	"os"
	"strconv"
)

// RequireEnvInt falls back to def if missing/invalid
func RequireEnvInt(key string, def int) int {
	if s := os.Getenv(key); s != "" {
		if i, err := strconv.Atoi(s); err == nil {
			return i
		}
		log.Printf("invalid %s=%q, using %d", key, s, def)
	}
	return def
}

// RequireEnvBool falls back to def if missing/invalid
func RequireEnvBool(key string, def bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
		log.Printf("invalid %s=%q, using %t", key, value, def)
	}
	return def
}
