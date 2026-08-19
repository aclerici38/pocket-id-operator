//go:build e2e
// +build e2e

package e2e

import (
	"encoding/base64"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// cimdMetadataURL is the OAuth Client ID Metadata Document this suite registers against.
// It is served from test/e2e/testdata/cimd-client-metadata.json in this repository via
// jsDelivr, which returns application/json (raw.githubusercontent.com returns text/plain,
// which Pocket-ID's fetcher rejects). The document's own client_id field must match this
// string exactly, and the shared instance allowlists it in e2e_suite_test.go.
//
// Pocket-ID's metadata fetcher refuses private, loopback and other special-use addresses
// with no runtime opt-out, so the document cannot be served from inside the cluster: this
// is why the URL is external and why the cluster needs egress to cdn.jsdelivr.net.
const cimdMetadataURL = "https://cdn.jsdelivr.net/gh/aclerici38/pocket-id-operator@main/" +
	"test/e2e/testdata/cimd-client-metadata.json"

var _ = Describe("Client ID Metadata Documents", Ordered, func() {
	It("advertises client_id_metadata_document_supported once the allowlist is set", func() {
		By("reading the instance's discovery document")
		script := fmt.Sprintf("curl -sf %s/.well-known/openid-configuration", formatInstanceURL())
		applyYAML(createCurlPodYAML("cimd-discovery", instanceNS, script))
		body := getPodLogs("cimd-discovery", instanceNS)
		kubectlDelete("pod", "cimd-discovery", instanceNS)

		By("verifying Pocket-ID enabled CIMD from CIMD_URL_ALLOWLIST")
		Expect(body).To(ContainSubstring(`"client_id_metadata_document_supported":true`),
			"spec.cimdUrlAllowlist should reach Pocket-ID as a JSON array and enable CIMD")
	})

	// Hermetic: no metadata document is fetched, because the point is that the operator
	// waits instead of registering a standard client under the document URL.
	It("waits for a CIMD client to be materialized instead of creating one", func() {
		const clientName = "test-cimd-awaiting"

		By("creating a PocketIDOIDCClient for a document that was never authorized against")
		createOIDCClient(OIDCClientOptions{
			Name:     clientName,
			ClientID: "https://apps.example.com/never-authorized/client-metadata.json",
		})
		DeferCleanup(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})

		By("verifying it reports AwaitingFirstAuthorization rather than going Ready")
		waitForConditionReason("pocketidoidcclient", clientName, userNS, "Ready", "AwaitingFirstAuthorization")

		By("verifying no client ID was ever assigned")
		// Asserted via the whole status, not jsonpath={.status.clientID}: kubectlGet returns
		// "" when the command itself fails, so an empty-string assertion cannot tell an
		// absent client ID from a broken query.
		Expect(kubectlGet("pocketidoidcclient", clientName, "-n", userNS, "-o", "jsonpath={.status}")).
			NotTo(ContainSubstring(`"clientID"`),
				"the operator must not create a client for an unmaterialized metadata document")
	})

	Context("with a materialized CIMD client", Ordered, func() {
		const clientName = "test-cimd-managed"

		BeforeAll(func() {
			By("checking the metadata document is published")
			requireCIMDDocumentReachable()

			By("triggering materialization via the unauthenticated device authorization endpoint")
			materializeCIMDClient()
		})

		It("adopts the client and records its type", func() {
			By("creating a PocketIDOIDCClient that sets only the fields Pocket-ID persists for CIMD")
			createOIDCClient(OIDCClientOptions{
				Name:                       clientName,
				ClientID:                   cimdMetadataURL,
				Description:                "managed by e2e",
				SkipConsent:                true,
				AccessTokenDurationMinutes: 15,
			})

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying status reports the adopted client")
			Expect(kubectlGet("pocketidoidcclient", clientName, "-n", userNS, "-o", "jsonpath={.status.clientType}")).
				To(Equal("cimd"))
			Expect(kubectlGet("pocketidoidcclient", clientName, "-n", userNS, "-o", "jsonpath={.status.clientID}")).
				To(Equal(cimdMetadataURL))
		})

		It("pushes the writable fields and leaves the metadata-owned ones alone", func() {
			body := getOIDCClientFromPocketID("cimd-verify", userNS, encodeCIMDClientID(cimdMetadataURL))

			By("verifying the fields Pocket-ID persists for a CIMD client were applied")
			Expect(body).To(ContainSubstring(`"description":"managed by e2e"`))
			Expect(body).To(ContainSubstring(`"skipConsent":true`))
			Expect(body).To(ContainSubstring(`"accessTokenDurationMinutes":15`))

			By("verifying the metadata document still owns name and callback URLs")
			Expect(body).To(ContainSubstring(`"clientType":"cimd"`))
			Expect(body).To(ContainSubstring(`"Pocket ID Operator E2E CIMD"`),
				"the operator must not overwrite the document-supplied client_name")
			Expect(body).To(ContainSubstring("https://cimd.example.com/callback"),
				"the operator must not overwrite the document-supplied redirect_uris")
		})

		// The drift loop this whole design exists to prevent: the operator diffs against
		// fields Pocket-ID discards, so it would push, read back, and push again forever.
		It("settles instead of drifting", func() {
			By("recording the current state and letting several reconciles pass")
			before := getOIDCClientFromPocketID("cimd-drift-1", userNS, encodeCIMDClientID(cimdMetadataURL))
			time.Sleep(30 * time.Second)
			after := getOIDCClientFromPocketID("cimd-drift-2", userNS, encodeCIMDClientID(cimdMetadataURL))

			Expect(after).To(Equal(before), "a managed CIMD client must reach a stable state")
			waitForReady("pocketidoidcclient", clientName, userNS)
		})

		// A CIMD client is reached through the API's cimdAccess rather than its own
		// spec.apiAccess, so status.cimdGrantedAPIs is the only place that access is visible
		// from the client side. It also has to stay read-only: the operator must report the
		// access without treating it as something it owns and revokes.
		Context("reached through an API's CIMD access", Ordered, func() {
			const (
				apiName     = "cimd-granted-api"
				apiResource = "https://cimd-granted.e2e.example.com"
			)

			BeforeAll(func() {
				By("creating an API that grants every CIMD client one permission")
				createAPIAndWaitReady(APIOptions{
					Name: apiName, Resource: apiResource,
					Permissions: []APIPermissionOption{
						{Key: "read:cimd", Name: "Read", CIMDAccess: true},
					},
				})
			})

			It("reports the API in status without claiming to manage it", func() {
				Eventually(func(g Gomega) {
					g.Expect(kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
						"-o", "jsonpath={.status.cimdGrantedAPIs[*]}")).To(Equal(apiResource))
				}, 2*time.Minute, 2*time.Second).Should(Succeed())

				By("verifying the operator claims no ownership of API-side access")
				Expect(kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.managedAPIs[*]}")).To(BeEmpty())
				Expect(kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.managedAPIPermissionIDs[*]}")).To(BeEmpty())
			})

			It("matches what Pocket-ID reports for the client", func() {
				body := getFromPocketID("cimd-granted-verify", userNS,
					"/api/api-access/"+encodeCIMDClientID(cimdMetadataURL)+"/apis")
				Expect(body).To(ContainSubstring(apiResource))
				Expect(body).To(ContainSubstring(`"cimdGrantedAccess":true`))
			})

			// The access is the API's to revoke. If the client reconcile ever tried to own it,
			// this would keep reporting an API the client can no longer reach.
			It("stops reporting the API once it revokes CIMD access", func() {
				createAPI(APIOptions{
					Name: apiName, Resource: apiResource,
					Permissions: []APIPermissionOption{
						{Key: "read:cimd", Name: "Read"},
					},
				})
				waitForReconciled("pocketidapi", apiName, userNS)

				Eventually(func(g Gomega) {
					g.Expect(kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
						"-o", "jsonpath={.status.cimdGrantedAPIs[*]}")).To(BeEmpty())
				}, 2*time.Minute, 2*time.Second).Should(Succeed())
			})

			AfterAll(func() {
				_ = kubectlDeleteWait("pocketidapi", apiName, userNS, time.Minute)
			})
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// encodeCIMDClientID mirrors the operator's path-parameter encoding: a CIMD client ID is a
// URL whose slashes cannot survive a path segment, so Pocket-ID accepts it base64url-encoded
// behind a "~" and decodes it in middleware.
func encodeCIMDClientID(id string) string {
	return "~" + base64.RawURLEncoding.EncodeToString([]byte(id))
}

// requireCIMDDocumentReachable fails the suite unless the metadata document resolves from
// inside the cluster with the content type and client_id Pocket-ID requires. It runs before
// the managed-client specs, which are the only coverage of adoption and of the anti-drift
// behaviour: skipping on an unreachable document would let that coverage disappear
// silently, which is exactly how a stale branch ref goes unnoticed.
func requireCIMDDocumentReachable() {
	script := fmt.Sprintf(`CODE=$(curl -s -o /tmp/doc -w '%%{http_code}' -H 'Accept: application/json' %q)
if [ "$CODE" != "200" ]; then echo "HTTP $CODE"; exit 0; fi
grep -q %q /tmp/doc && echo reachable || echo "client_id in the document does not match its URL"`,
		cimdMetadataURL, cimdMetadataURL)

	applyYAML(createCurlPodYAML("cimd-preflight", instanceNS, script))
	out := getPodLogs("cimd-preflight", instanceNS)
	kubectlDelete("pod", "cimd-preflight", instanceNS)

	Expect(out).To(Equal("reachable"),
		"the metadata document at %s is not usable (%s).\nIt is served from this repo via "+
			"jsDelivr, so cimdMetadataURL and the document's own client_id field must both name "+
			"the branch the file is pushed to — see the TODO on cimdMetadataURL.",
		cimdMetadataURL, out)
}

// materializeCIMDClient makes Pocket-ID fetch the metadata document and persist the client.
// POST /api/oidc/device/authorize needs no session and no client authentication (a CIMD
// client is always public), and the CIMD resolver is wired into fosite as its ClientResolver,
// so the client is resolved on any OAuth flow rather than only a browser /authorize.
func materializeCIMDClient() {
	script := fmt.Sprintf(`RESPONSE=$(curl -s -w '\n%%{http_code}' -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'client_id=%s' \
  --data-urlencode 'scope=openid' \
  %s/api/oidc/device/authorize)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "$BODY"
if [ "$HTTP_CODE" != "200" ]; then
  echo "device authorization failed with HTTP $HTTP_CODE" >&2
  exit 1
fi`, cimdMetadataURL, formatInstanceURL())

	applyYAML(createCurlPodYAML("cimd-materialize", instanceNS, script))
	body := getPodLogs("cimd-materialize", instanceNS)
	kubectlDelete("pod", "cimd-materialize", instanceNS)

	Expect(body).To(ContainSubstring("device_code"),
		"the device authorization request should have resolved and materialized the CIMD client")
}
