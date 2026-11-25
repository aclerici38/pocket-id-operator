package helpers

import (
	"cmp"
	"slices"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// CustomClaimsToPocketID converts CR custom claims into the full set Pocket-ID replaces a
// resource's claims with. It is never nil, so an empty set clears the claims.
func CustomClaimsToPocketID(claims []pocketidv1alpha1.CustomClaim) []pid.CustomClaimCreateDto {
	result := make([]pid.CustomClaimCreateDto, 0, len(claims))
	for _, claim := range claims {
		result = append(result, pid.CustomClaimCreateDto{Key: claim.Key, Value: claim.Value})
	}
	return result
}

// CustomClaimsFromPocketID converts Pocket-ID custom claims into the CR representation, sorted
// by key since Pocket-ID returns them unordered.
func CustomClaimsFromPocketID(claims []pid.CustomClaimDto) []pocketidv1alpha1.CustomClaim {
	if len(claims) == 0 {
		return nil
	}
	result := make([]pocketidv1alpha1.CustomClaim, 0, len(claims))
	for _, claim := range claims {
		result = append(result, pocketidv1alpha1.CustomClaim{Key: claim.Key, Value: claim.Value})
	}
	slices.SortFunc(result, func(a, b pocketidv1alpha1.CustomClaim) int { return cmp.Compare(a.Key, b.Key) })
	return result
}
