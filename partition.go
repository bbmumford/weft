package weft

import (
	"context"
	"sort"
)

// Opaque partition carriers: the axis-keyed scope values a store selector keys
// on, stamped once by an authority layer and read by handlers via
// ExtractPartition. An axis is a name the CONSUMER chooses and weft never
// interprets — weft cannot tell one axis from another, holds no list of valid
// axes, and gives no axis precedence over another. A consumer needing two
// nested scopes stamps two axes and decides itself which one a query selects on.
//
// Separate from the SUBJECT carriers in authcontext.go on purpose: those name
// who is calling and what they may do, these name which slice of data the call
// reaches. SetAuthContext stamping a subject must never widen a partition, so
// the two never share a key.
//
// Keys are weft-package-scoped by the unexported contextKey type (context.go),
// so a value stamped through another package's carrier is invisible here. A
// consumer swaps its stamp and its reads to these together: a stamp left on the
// old carrier reads back "" here, which is indistinguishable from an
// unpartitioned request rather than an error.
const partitionsKey = contextKey("partitions")

// WithPartition stamps one axis value onto ctx, leaving every other axis as it
// was, and returns a context carrying the merged set.
//
// An empty axis or an empty value is a no-op: it returns ctx unchanged rather
// than storing a blank. A blank must not be storable because ExtractPartition
// reports absent and stamped-empty identically, so a stored blank would let a
// later write silently erase an axis a caller was already scoped to — narrowing
// or widening authority with no signal at the call site.
//
// The stored map is copied on every write. Contexts share structure with their
// parents, so mutating the map in place would make a stamp added deep in one
// request's handler chain visible to the parent context and to anything else
// holding it — one request's partition reaching another's reads.
func WithPartition(ctx context.Context, axis, value string) context.Context {
	if axis == "" || value == "" {
		return ctx
	}
	current := partitionMap(ctx)
	next := make(map[string]string, len(current)+1)
	for k, v := range current {
		next[k] = v
	}
	next[axis] = value
	return context.WithValue(ctx, partitionsKey, next)
}

// WithPartitions REPLACES the whole partition set with snapshot, dropping any
// axis not present in it.
//
// Replace rather than merge because this is what a boundary that rebuilds
// identity from a verified source calls: merging would let one axis survive
// from a previous stamp while the rest are rebuilt, producing a set that never
// existed at any single point of authority. Pass the complete set the caller is
// scoped to, or use WithPartition to add one axis to what is already there.
//
// Entries with an empty axis or empty value are dropped, for the reason given on
// WithPartition. An empty or all-blank snapshot clears the set, so a caller that
// means "no change" must not call this.
func WithPartitions(ctx context.Context, snapshot map[string]string) context.Context {
	next := make(map[string]string, len(snapshot))
	for k, v := range snapshot {
		if k == "" || v == "" {
			continue
		}
		next[k] = v
	}
	return context.WithValue(ctx, partitionsKey, next)
}

// ExtractPartition reads the value stamped for axis, or "" when that axis was
// never stamped.
//
// "" means the request is not scoped on this axis. A store selector must treat
// it as a denial and refuse to read, not as a wildcard: returning every
// partition's rows for an unstamped request is how an unscoped query reads
// across partitions.
func ExtractPartition(ctx context.Context, axis string) string {
	return partitionMap(ctx)[axis]
}

// PartitionAxes returns the stamped axis names in sorted order, for a caller
// serialising the set onto a wire map or an audit record. Sorted so that record
// is byte-stable across requests carrying the same axes; Go's map iteration
// order is not.
func PartitionAxes(ctx context.Context) []string {
	current := partitionMap(ctx)
	axes := make([]string, 0, len(current))
	for k := range current {
		axes = append(axes, k)
	}
	sort.Strings(axes)
	return axes
}

// Partitions returns a copy of the whole stamped set, for a caller forwarding it
// across a boundary. It is a copy so a caller cannot reach back through the
// returned map and change what later readers of this context see.
func Partitions(ctx context.Context) map[string]string {
	current := partitionMap(ctx)
	out := make(map[string]string, len(current))
	for k, v := range current {
		out[k] = v
	}
	return out
}

// partitionMap returns the stored set, or an empty map when nothing was stamped
// or when the key holds some other type. Callers must not write to the result:
// it is the stored map itself, shared with every context derived from this one.
func partitionMap(ctx context.Context) map[string]string {
	if m, ok := ctx.Value(partitionsKey).(map[string]string); ok {
		return m
	}
	return map[string]string{}
}
