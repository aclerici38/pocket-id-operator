package helpers

import (
	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// CustomClaimsToPocketID converts CR custom claims into the client representation.
func CustomClaimsToPocketID(claims []pocketidv1alpha1.CustomClaim) []pocketid.CustomClaim {
	if len(claims) == 0 {
		return nil
	}
	result := make([]pocketid.CustomClaim, 0, len(claims))
	for _, claim := range claims {
		result = append(result, pocketid.CustomClaim{Key: claim.Key, Value: claim.Value})
	}
	return result
}

// CustomClaimsFromPocketID converts client custom claims into the CR representation.
func CustomClaimsFromPocketID(claims []pocketid.CustomClaim) []pocketidv1alpha1.CustomClaim {
	if len(claims) == 0 {
		return nil
	}
	result := make([]pocketidv1alpha1.CustomClaim, 0, len(claims))
	for _, claim := range claims {
		result = append(result, pocketidv1alpha1.CustomClaim{Key: claim.Key, Value: claim.Value})
	}
	return result
}
