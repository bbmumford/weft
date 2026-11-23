/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"net/http"
)

// Swap instructs htmx to fetch the given URL and swap it into the target using the provided swap strategy.
// It sets HX-Location, HX-Retarget, and HX-Reswap (when provided) and returns 204 No Content.
func Swap(w http.ResponseWriter, url, target, swap string) {
	if target != "" {
		w.Header().Set("HX-Retarget", target)
	}
	if swap != "" {
		w.Header().Set("HX-Reswap", swap)
	}
	w.Header().Set("HX-Location", url)
	w.WriteHeader(http.StatusNoContent)
}

// Redirect performs a full-page navigation via HX-Redirect and returns 204 No Content.
func Redirect(w http.ResponseWriter, url string) {
	w.Header().Set("HX-Redirect", url)
	w.WriteHeader(http.StatusNoContent)
}
