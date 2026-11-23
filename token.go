/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// GenerateShortLivedToken generates a random token that expires in the given duration.
// In a production system, you might instead sign a JWT or similar.
func GenerateShortLivedToken(validity time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// A simple token can be a base64 encoded random string.
	return base64.URLEncoding.EncodeToString(b), nil
}
