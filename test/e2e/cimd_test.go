//go:build e2e
// +build e2e

package e2e

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
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
		body := getFromPocketID("/.well-known/openid-configuration")

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
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})

		By("verifying it reports AwaitingFirstAuthorization rather than going Ready")
		waitForConditionReason("pocketidoidcclient", clientName, userNS, "Ready", "AwaitingFirstAuthorization")

		By("verifying no client ID was ever assigned")
		// Asserted via the whole status, not jsonpath={.status.clientID}: kubectlGet returns
		// "" when the command itself fails, so an empty-string assertion cannot tell an
		// absent client ID from a broken query.
		Expect(getField("pocketidoidcclient", clientName, userNS, ".status")).
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
			Expect(getField("pocketidoidcclient", clientName, userNS, ".status.clientType")).
				To(Equal("cimd"))
			Expect(getField("pocketidoidcclient", clientName, userNS, ".status.clientID")).
				To(Equal(cimdMetadataURL))
		})

		It("pushes the writable fields and leaves the metadata-owned ones alone", func() {
			body := getOIDCClientFromPocketID(encodeCIMDClientID(cimdMetadataURL))

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
			before := getOIDCClientFromPocketID(encodeCIMDClientID(cimdMetadataURL))
			time.Sleep(30 * time.Second)
			after := getOIDCClientFromPocketID(encodeCIMDClientID(cimdMetadataURL))

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
					g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.cimdGrantedAPIs[*]")).To(Equal(apiResource))
				}).Should(Succeed())

				By("verifying the operator claims no ownership of API-side access")
				Expect(getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIs[*]")).To(BeEmpty())
				Expect(getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIPermissionIDs[*]")).To(BeEmpty())
			})

			It("matches what Pocket-ID reports for the client", func() {
				body := getFromPocketID("/api/api-access/" + encodeCIMDClientID(cimdMetadataURL) + "/apis")
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
					g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.cimdGrantedAPIs[*]")).To(BeEmpty())
				}).Should(Succeed())
			})

			AfterAll(func() {
				_ = deleteObjectAndWait("pocketidapi", apiName, userNS, time.Minute)
			})
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
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

// requireCIMDDocumentReachable fails fast, with a message that explains the fix, when the
// metadata document is missing or self-inconsistent. It is fetched from the test binary
// rather than from inside the cluster: this is a preflight on the document itself, and if
// the cluster's egress is what is broken, materializeCIMDClient reports that separately.
func requireCIMDDocumentReachable() {
	GinkgoHelper()

	ctx, cancel := testCtx()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cimdMetadataURL, nil)
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred(), "fetching %s", cimdMetadataURL)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())

	const hint = "It is served from this repo via jsDelivr, so cimdMetadataURL and the " +
		"document's own client_id field must both name the branch the file is pushed to " +
		"— see the TODO on cimdMetadataURL."

	Expect(resp.StatusCode).To(Equal(http.StatusOK),
		"the metadata document at %s is not usable (HTTP %d).\n%s", cimdMetadataURL, resp.StatusCode, hint)
	Expect(string(body)).To(ContainSubstring(cimdMetadataURL),
		"the client_id in the document at %s does not match its URL.\n%s", cimdMetadataURL, hint)
}

// materializeCIMDClient makes Pocket-ID fetch the metadata document and persist the
// client. POST /api/oidc/device/authorize needs no session and no client authentication
// (a CIMD client is always public), and the CIMD resolver is wired into fosite as its
// ClientResolver, so the client is resolved on any OAuth flow rather than only a browser
// /authorize.
func materializeCIMDClient() {
	GinkgoHelper()

	ctx, cancel := testCtx()
	defer cancel()

	form := url.Values{
		"client_id": []string{cimdMetadataURL},
		"scope":     []string{"openid"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		pocketIDBaseURL()+"/api/oidc/device/authorize", strings.NewReader(form.Encode()))
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred(), "requesting device authorization")
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())

	Expect(resp.StatusCode).To(Equal(http.StatusOK),
		"device authorization failed with HTTP %d: %s", resp.StatusCode, body)
	Expect(string(body)).To(ContainSubstring("device_code"),
		"the device authorization request should have resolved and materialized the CIMD client")
}
