package weft

import (
	"context"
	"reflect"
	"testing"
)

func TestPartition_RoundTrip(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	if got := ExtractPartition(ctx, "estate"); got != "e-1" {
		t.Fatalf("ExtractPartition = %q, want %q", got, "e-1")
	}
}

func TestPartition_AbsentAxisReadsEmpty(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	if got := ExtractPartition(ctx, "never-stamped"); got != "" {
		t.Fatalf("unstamped axis = %q, want \"\"", got)
	}
	if got := ExtractPartition(context.Background(), "estate"); got != "" {
		t.Fatalf("bare context = %q, want \"\"", got)
	}
}

func TestPartition_IndependentAxesDoNotOverwrite(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	ctx = WithPartition(ctx, "region", "r-9")
	if got := ExtractPartition(ctx, "estate"); got != "e-1" {
		t.Fatalf("estate = %q after stamping region, want e-1", got)
	}
	if got := ExtractPartition(ctx, "region"); got != "r-9" {
		t.Fatalf("region = %q, want r-9", got)
	}
}

// A child's stamp must not reach the parent context. Contexts share structure,
// so a WithPartition that mutated the stored map in place would make one
// request's partition visible to anything else holding the parent.
func TestPartition_ChildStampIsInvisibleToParent(t *testing.T) {
	parent := WithPartition(context.Background(), "estate", "e-1")
	child := WithPartition(parent, "estate", "e-2")
	sibling := WithPartition(parent, "region", "r-9")

	if got := ExtractPartition(parent, "estate"); got != "e-1" {
		t.Fatalf("parent estate = %q after child stamped e-2, want e-1", got)
	}
	if got := ExtractPartition(parent, "region"); got != "" {
		t.Fatalf("parent region = %q after sibling stamped it, want \"\"", got)
	}
	if got := ExtractPartition(child, "estate"); got != "e-2" {
		t.Fatalf("child estate = %q, want e-2", got)
	}
	if got := ExtractPartition(sibling, "estate"); got != "e-1" {
		t.Fatalf("sibling lost inherited estate = %q, want e-1", got)
	}
}

func TestPartition_EmptyAxisOrValueCannotEraseAStampedAxis(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	if got := ExtractPartition(WithPartition(ctx, "estate", ""), "estate"); got != "e-1" {
		t.Fatalf("empty value erased the axis: %q, want e-1", got)
	}
	if got := ExtractPartition(WithPartition(ctx, "", "e-2"), "estate"); got != "e-1" {
		t.Fatalf("empty axis disturbed the set: %q, want e-1", got)
	}
	if axes := PartitionAxes(WithPartition(ctx, "", "")); !reflect.DeepEqual(axes, []string{"estate"}) {
		t.Fatalf("blank stamp changed the axis set: %v", axes)
	}
}

func TestPartitions_ReplacesRatherThanMerges(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	ctx = WithPartition(ctx, "region", "r-9")
	ctx = WithPartitions(ctx, map[string]string{"estate": "e-2"})

	if got := ExtractPartition(ctx, "estate"); got != "e-2" {
		t.Fatalf("estate = %q, want e-2", got)
	}
	if got := ExtractPartition(ctx, "region"); got != "" {
		t.Fatalf("region survived a replacing snapshot = %q, want \"\"", got)
	}
}

func TestPartitions_DropsBlankEntries(t *testing.T) {
	ctx := WithPartitions(context.Background(), map[string]string{
		"estate": "e-1",
		"":       "orphan",
		"region": "",
	})
	if axes := PartitionAxes(ctx); !reflect.DeepEqual(axes, []string{"estate"}) {
		t.Fatalf("axes = %v, want [estate]", axes)
	}
}

func TestPartitionAxes_SortedAndStable(t *testing.T) {
	ctx := WithPartitions(context.Background(), map[string]string{
		"region": "r", "estate": "e", "aisle": "a",
	})
	want := []string{"aisle", "estate", "region"}
	for i := 0; i < 20; i++ {
		if got := PartitionAxes(ctx); !reflect.DeepEqual(got, want) {
			t.Fatalf("PartitionAxes = %v, want %v", got, want)
		}
	}
}

// The returned map must be a copy: a caller that forwards the set and then
// writes to what it got back must not change what later readers of this
// context see.
func TestPartitions_ReturnedMapIsACopy(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	got := Partitions(ctx)
	got["estate"] = "tampered"
	got["region"] = "injected"

	if v := ExtractPartition(ctx, "estate"); v != "e-1" {
		t.Fatalf("estate = %q after mutating the returned map, want e-1", v)
	}
	if v := ExtractPartition(ctx, "region"); v != "" {
		t.Fatalf("region = %q after mutating the returned map, want \"\"", v)
	}
}

// The subject carriers and the partition carriers must not reach each other:
// stamping who is calling can never set which data they reach.
func TestPartition_NoCollisionWithSubjectCarriers(t *testing.T) {
	ctx := SetAuthContext(context.Background(), "u-1", []string{"a.read"}, "session")
	ctx = WithSessionID(ctx, "s-1")
	for _, axis := range []string{"user_id", "scopes", "auth_type", "session_id", "authenticated"} {
		if got := ExtractPartition(ctx, axis); got != "" {
			t.Fatalf("subject carrier leaked into partition axis %q = %q", axis, got)
		}
	}
	if axes := PartitionAxes(ctx); len(axes) != 0 {
		t.Fatalf("SetAuthContext created partition axes: %v", axes)
	}

	pctx := WithPartition(context.Background(), "estate", "e-1")
	if got := ExtractUserID(pctx); got != "" {
		t.Fatalf("partition stamp created a subject id: %q", got)
	}
	if IsAuthenticated(pctx) {
		t.Fatal("partition stamp authenticated the request")
	}
}

func TestPartition_ForeignValueUnderTheKeyReadsAsUnstamped(t *testing.T) {
	ctx := context.WithValue(context.Background(), partitionsKey, "not-a-map")
	if got := ExtractPartition(ctx, "estate"); got != "" {
		t.Fatalf("estate = %q, want \"\"", got)
	}
	if axes := PartitionAxes(ctx); len(axes) != 0 {
		t.Fatalf("axes = %v, want none", axes)
	}
}
