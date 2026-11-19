package helpers

import (
	"slices"
	"testing"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func TestCustomClaimsToPocketID(t *testing.T) {
	got := CustomClaimsToPocketID([]pocketidv1alpha1.CustomClaim{
		{Key: "level", Value: "3"},
		{Key: "department", Value: "engineering"},
	})
	want := []pid.CustomClaimCreateDto{
		{Key: "level", Value: "3"},
		{Key: "department", Value: "engineering"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// The result replaces the full claim set, so no claims has to go out as [] rather than null.
func TestCustomClaimsToPocketID_EmptyIsNotNil(t *testing.T) {
	if got := CustomClaimsToPocketID(nil); got == nil || len(got) != 0 {
		t.Errorf("got %#v, want an empty non-nil slice", got)
	}
}

// Pocket-ID returns claims unordered, so status is sorted to stay stable.
func TestCustomClaimsFromPocketID_SortsByKey(t *testing.T) {
	got := CustomClaimsFromPocketID([]pid.CustomClaimDto{
		{Key: "level", Value: "3"},
		{Key: "department", Value: "engineering"},
	})
	want := []pocketidv1alpha1.CustomClaim{
		{Key: "department", Value: "engineering"},
		{Key: "level", Value: "3"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCustomClaimsFromPocketID_EmptyIsNil(t *testing.T) {
	if got := CustomClaimsFromPocketID([]pid.CustomClaimDto{}); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
