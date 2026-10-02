//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

var _ = Describe("OIDC Client Federated Identity Public Keys", Ordered, func() {
	// Pocket-ID re-encodes every key it stores, so the operator only stays quiet if what comes
	// back still compares equal to the spec. Keys are not validated by the operator either:
	// Pocket-ID's rejection has to reach the resource.

	const (
		clientName    = "test-public-keys"
		configMapName = "test-public-keys-jwks"
		issuer        = "https://public-keys.example.com"
		okpKey        = `{"kty":"OKP","crv":"Ed25519","kid":"e2e-key","use":"sig","x":"fxAuz6i2oJCZM8blM5bge1smljJn8qL-yysBgwHBnDA"}`
		rsaKey1       = `{"use":"sig","kty":"RSA","kid":"rsa-1","alg":"RS256","n":"pqjQIWuaoZnXJ-jAOlk9RYGsbpxCutvBX9jQbEvRBUoNFUxYF_G619NmXCTDIHW8B1Aje6XjGMbqjrTpvxe4NB03u_P-64Q1dfoZj91xR2O5ENjVG_-9Vnpc_BXajp2zT_bJWGhd9AIHRanZwnmnbADRslOniA_Q00rVDcjaE-EugJq0vEL5okd7z9l0FNEVPmFrJ7beLk9Dh1udNST8fBzCt91nYKQu3nI7rO_izN4VbT-F2FmY-dIY4a1IlxYn606b283gMQj8IRz8VhVNojJp-gRpr67zRwfCHO_QF-ZszBI4Vz5iyQh0DEiNqDEpVSMDkvmG-CI4_jNqpqJKoQ","e":"AQAB"}`
		rsaKey2       = `{"use":"sig","kty":"RSA","kid":"rsa-2","alg":"RS256","n":"0l7shn_E5PGe9nHzhJAuqTp7-qwegnQselTxYC64d7mL_wg49u3GYFZs9wZADLpJJfVjM8ta8B8HyDgGp-Cm-4lMDxp2P46pE9xw3Ya0nuYZ3dxqXtAwmBPzvjg9E5XliI_o6uChVi_CgavtwKhaPKfG-hqtBYL0lWenOmff9mBOr5_VmHcon_hzybVAvAn6Bhx_RwuuLTEo1eQPpNr-xmRRdR8JGDw7uOhroc9-3m41o6CpXFZkylHmIq3IBPyXsAAdAAYlN8RNZFu6YgV5C39aB5kMTQB23KW5VK_fKmcztFQ_GAkOuKokarQX3ASrRB1bqQ3_itZsOLJqtP9zIQ","e":"AQAB"}`
	)

	var clientID string

	applyJWKS := func(keys ...string) {
		jwks, err := json.Marshal(map[string][]json.RawMessage{"keys": rawKeys(keys...)})
		Expect(err).NotTo(HaveOccurred())
		applyYAML(fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
  namespace: %s
data:
  jwks.json: '%s'
`, configMapName, userNS, jwks))
	}

	// inSync is the operator's own comparison, so true means the next reconcile pushes nothing.
	inSync := func(keys ...string) bool {
		want := []pocketid.OIDCClientFederatedIdentity{{Issuer: issuer, PublicKeys: rawKeys(keys...)}}
		got := federatedIdentitiesFromPocketID(clientID)
		return pocketid.OIDCClientInput{Credentials: &pocketid.OIDCClientCredentials{FederatedIdentities: want}}.
			Equal(pocketid.OIDCClientInput{Credentials: &pocketid.OIDCClientCredentials{FederatedIdentities: got}})
	}

	BeforeAll(func() {
		applyJWKS(rsaKey1)
	})

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		deleteObject("configmap", configMapName, userNS)
	})

	It("should store inline and referenced keys as the spec declares them", func() {
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://public-keys.example.com/callback"},
			FederatedIdentities: []FederatedIdentity{{
				Issuer: issuer,
				PublicKeys: []string{
					`{"value": ` + okpKey + `}`,
					fmt.Sprintf(`{"valueFrom": {"configMapKeyRef": {"name": %q, "key": "jwks.json"}}}`, configMapName),
				},
			}},
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		Expect(inSync(okpKey, rsaKey1)).To(BeTrue(), "Pocket-ID returned keys that differ from the spec: %s",
			federatedIdentitiesFromPocketID(clientID))
	})

	It("should pick up a key published to the referenced JWKS", func() {
		applyJWKS(rsaKey1, rsaKey2)

		Eventually(func() bool { return inSync(okpKey, rsaKey1, rsaKey2) }).Should(BeTrue())
		waitForReady("pocketidoidcclient", clientName, userNS)
	})

	It("should report a key Pocket-ID rejects", func() {
		Expect(patchObject("pocketidoidcclient", clientName, userNS, fmt.Sprintf(
			`{"spec":{"federatedIdentities":[{"issuer":%q,"publicKeys":[{"value":{"kty":"OKP","crv":"Ed25519","x":"fxAuz6i2oJCZM8blM5bge1smljJn8qL-yysBgwHBnDA"}}]}]}}`,
			issuer))).To(Succeed())

		Eventually(func() string {
			return getField("pocketidoidcclient", clientName, userNS, ".status.conditions[?(@.type=='Ready')].message")
		}).Should(ContainSubstring("invalid public key"))
		Expect(inSync(okpKey, rsaKey1, rsaKey2)).To(BeTrue(), "a rejected update must leave the stored keys alone")
	})
})

func rawKeys(keys ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(keys))
	for i, key := range keys {
		out[i] = json.RawMessage(key)
	}
	return out
}
