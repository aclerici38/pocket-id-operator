package helpers

import (
	"testing"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

func TestCustomClaimsToPocketID_MapsAllClaimsInOrder(t *testing.T) {
	got := CustomClaimsToPocketID([]pocketidv1alpha1.CustomClaim{
		{Key: "department", Value: "engineering"},
		{Key: "level", Value: "3"},
	})

	want := []pocketid.CustomClaim{
		{Key: "department", Value: "engineering"},
		{Key: "level", Value: "3"},
	}
	if len(got) != len(want) {
		t.Fatalf("length: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("claim %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// A nil result signals "no claims declared" to the callers, which treat nil and
// empty alike, so both inputs have to collapse to nil.
func TestCustomClaimsToPocketID_EmptyInputsReturnNil(t *testing.T) {
	if got := CustomClaimsToPocketID(nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := CustomClaimsToPocketID([]pocketidv1alpha1.CustomClaim{}); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
}

func TestCustomClaimsFromPocketID_MapsAllClaimsInOrder(t *testing.T) {
	got := CustomClaimsFromPocketID([]pocketid.CustomClaim{
		{Key: "department", Value: "engineering"},
		{Key: "level", Value: "3"},
	})

	want := []pocketidv1alpha1.CustomClaim{
		{Key: "department", Value: "engineering"},
		{Key: "level", Value: "3"},
	}
	if len(got) != len(want) {
		t.Fatalf("length: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("claim %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestCustomClaimsFromPocketID_EmptyInputsReturnNil(t *testing.T) {
	if got := CustomClaimsFromPocketID(nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := CustomClaimsFromPocketID([]pocketid.CustomClaim{}); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
}

// Round-tripping is how a pushed claim set becomes observed status, so the two
// converters have to agree on the representation.
func TestCustomClaims_RoundTripPreservesClaims(t *testing.T) {
	original := []pocketidv1alpha1.CustomClaim{
		{Key: "department", Value: "engineering"},
		{Key: "level", Value: "3"},
	}

	got := CustomClaimsFromPocketID(CustomClaimsToPocketID(original))
	if len(got) != len(original) {
		t.Fatalf("length: got %d, want %d", len(got), len(original))
	}
	for i := range original {
		if got[i] != original[i] {
			t.Errorf("claim %d: got %v, want %v", i, got[i], original[i])
		}
	}
}
