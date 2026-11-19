//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"
)

var _ = Describe("SCIM Service Provider", Ordered, func() {
	// These tests verify that the operator correctly manages SCIM service provider
	// configurations in Pocket-ID when spec.scim is set on a PocketIDOIDCClient. A client is
	// only Ready once its provider synced, so the endpoints point at an in-cluster stub.
	const stubName = "scim-stub"
	scimURL := func(path string) string { return fmt.Sprintf("http://%s.%s.svc:8080%s", stubName, userNS, path) }

	BeforeAll(func() {
		deploySCIMStub(stubName)
	})

	AfterAll(func() {
		deleteObject("pod", stubName, userNS)
		deleteObject("service", stubName, userNS)
	})

	Context("Basic SCIM lifecycle", func() {
		const clientName = "test-scim-basic"

		It("should create a SCIM service provider when spec.scim is set", func() {
			By("creating an OIDC client with a SCIM endpoint")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: scimURL("/v2"),
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider ID is populated in status")
			scimID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(scimID).NotTo(BeEmpty())

			By("verifying the SCIM provider exists in Pocket-ID via API")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			scimEndpoint := getSCIMProviderEndpoint(oidcClientID)
			Expect(scimEndpoint).To(Equal(scimURL("/v2")))
		})

		It("should update the SCIM service provider when the endpoint changes", func() {
			By("updating the OIDC client with a new SCIM endpoint")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: scimURL("/v2-updated"),
				},
			}))

			By("waiting for the change to propagate")
			oidcClientID := getField("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Eventually(func(g Gomega) {
				endpoint := getSCIMProviderEndpoint(oidcClientID)
				g.Expect(endpoint).To(Equal(scimURL("/v2-updated")))
			}).Should(Succeed())

			By("verifying the OIDC client is still ready")
			waitForReady("pocketidoidcclient", clientName, userNS)
		})

		It("should delete the SCIM service provider when spec.scim is removed", func() {
			By("getting the current SCIM provider ID")
			scimID := getField("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(scimID).NotTo(BeEmpty())

			By("removing spec.scim from the OIDC client")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
			}))

			By("waiting for the SCIM provider ID to be cleared from status")
			Eventually(func(g Gomega) {
				id := getField("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
				g.Expect(id).To(BeEmpty())
			}).Should(Succeed())

			By("verifying the OIDC client is still ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider no longer exists in Pocket-ID")
			oidcClientID := getField("pocketidoidcclient", clientName, userNS, ".status.clientID")
			scimExists := checkSCIMProviderExists(oidcClientID)
			Expect(scimExists).To(BeFalse())
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM with bearer token from Secret", func() {
		const clientName = "test-scim-token"
		const secretName = "scim-bearer-token"

		BeforeAll(func() {
			By("creating the bearer token Secret")
			applyYAML(createSecretYAML(secretName, userNS, map[string]string{
				"token": "my-super-secret-token",
			}))
		})

		It("should create a SCIM provider using a bearer token from a Secret", func() {
			By("creating an OIDC client with SCIM and token reference")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: scimURL("/v2"),
					TokenSecretRef: &SecretKeyRef{
						Name: secretName,
						Key:  "token",
					},
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider ID is populated in status")
			scimID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(scimID).NotTo(BeEmpty())

			By("verifying the SCIM provider was created in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			scimEndpoint := getSCIMProviderEndpoint(oidcClientID)
			Expect(scimEndpoint).To(Equal(scimURL("/v2")))
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
			deleteObject("secret", secretName, userNS)
		})
	})

	Context("SCIM deletion on OIDC client delete", func() {
		const clientName = "test-scim-delete-cleanup"

		It("should delete the SCIM provider when the OIDC client CR is deleted", func() {
			By("creating an OIDC client with SCIM configured")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: scimURL("/cleanup"),
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("recording the OIDC client ID and SCIM provider ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			scimID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(scimID).NotTo(BeEmpty())

			By("deleting the OIDC client CR")
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider no longer exists in Pocket-ID")
			Eventually(func(g Gomega) {
				deleteObject("pod", "verify-scim-gone-after-oidc-delete", userNS)
				gone := checkSCIMProviderGone(oidcClientID)
				g.Expect(gone).To(BeTrue(), "SCIM provider should be deleted after OIDC client deletion")
			}).Should(Succeed())
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM adoption of existing provider", func() {
		const clientName = "test-scim-adopt"

		It("should adopt a pre-existing SCIM provider when taking over an existing OIDC client", func() {
			By("creating an OIDC client directly in Pocket-ID with a SCIM provider")
			pocketIDClientID := "scim-adopt-test-client"
			createOIDCClientInPocketID(pocketIDClientID, "SCIM Adopt Test",
				[]string{"https://adopt-scim.example.com/callback"})
			scimID := createSCIMProviderInPocketID(pocketIDClientID, scimURL("/pre-existing"))

			By("creating a PocketIDOIDCClient CR with spec.scim set, adopting the existing OIDC client")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name:     clientName,
				ClientID: pocketIDClientID,
				SCIM: &SCIMConfig{
					Endpoint: scimURL("/pre-existing"),
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the operator adopted the existing SCIM provider (same ID)")
			adoptedSCIMID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(adoptedSCIMID).To(Equal(scimID), "operator should adopt the pre-existing SCIM provider")
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM sync on every reconcile", func() {
		const clientName = "test-scim-resync"

		It("should sync the provider again on a later reconcile without changing it", func() {
			By("creating an OIDC client with a SCIM endpoint")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: scimURL("/resync"),
				},
			}))
			waitForReady("pocketidoidcclient", clientName, userNS)
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("recording the first sync, which Ready waits for")
			first := getSCIMProvider(oidcClientID)
			Expect(first.Endpoint).To(Equal(scimURL("/resync")))
			Expect(first.LastSyncedAt).NotTo(BeEmpty())

			By("waiting for another reconcile to sync again")
			Expect(annotateObject("pocketidoidcclient", clientName, userNS, "test/trigger-reconcile=1")).To(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(getSCIMProvider(oidcClientID).LastSyncedAt).NotTo(Equal(first.LastSyncedAt))
			}).Should(Succeed())
			Expect(getSCIMProvider(oidcClientID).Endpoint).To(Equal(scimURL("/resync")))
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM sync failure", func() {
		const clientName = "test-scim-unreachable"

		It("should report not ready when the SCIM endpoint can't be synced", func() {
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: fmt.Sprintf("http://scim-missing.%s.svc:8080/v2", userNS),
				},
			}))
			waitForConditionReason("pocketidoidcclient", clientName, userNS, "Ready", "SCIMSyncError")
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM stale cleanup on adoption without spec.scim", func() {
		const clientName = "test-scim-stale-cleanup"

		It("should delete a stale SCIM provider when adopting an OIDC client without spec.scim", func() {
			By("creating an OIDC client directly in Pocket-ID with a SCIM provider")
			pocketIDClientID := "scim-stale-cleanup-client"
			createOIDCClientInPocketID(pocketIDClientID, "SCIM Stale Cleanup Test",
				[]string{"https://stale-scim.example.com/callback"})
			scimID := createSCIMProviderInPocketID(pocketIDClientID,
				"https://scim-stale.example.com/v2")

			By("creating a PocketIDOIDCClient CR without spec.scim, adopting the existing OIDC client")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name:     clientName,
				ClientID: pocketIDClientID,
				// Note: no SCIM spec — operator should clean up the stale SCIM provider
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the stale SCIM provider was deleted from Pocket-ID")
			_ = scimID
			Eventually(func(g Gomega) {
				deleteObject("pod", "verify-stale-scim-gone", userNS)
				gone := checkSCIMProviderGone(pocketIDClientID)
				g.Expect(gone).To(BeTrue(), "stale SCIM provider should be deleted")
			}).Should(Succeed())

			By("verifying the scimProviderID status field is empty")
			id := getField("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(id).To(BeEmpty())
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// --- SCIM API Helpers ---

// deploySCIMStub runs a pod and Service on port 8080 that accept any SCIM sync: lists are
// empty, and creates and updates echo the resource back with an ID.
func deploySCIMStub(name string) {
	GinkgoHelper()

	applyYAML(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
spec:
  containers:
  - name: stub
    image: mirror.gcr.io/library/python:alpine
    command: ["python", "-u", "-c"]
    args:
    - |
      import http.server, json, uuid
      class Handler(http.server.BaseHTTPRequestHandler):
          def reply(self, code, body=None):
              data = json.dumps(body).encode() if body is not None else b""
              self.send_response(code)
              self.send_header("Content-Type", "application/scim+json")
              self.send_header("Content-Length", str(len(data)))
              self.end_headers()
              self.wfile.write(data)
          def body(self):
              return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
          def do_GET(self):
              self.reply(200, {"Resources": [], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0})
          def do_POST(self):
              self.reply(201, {**self.body(), "id": str(uuid.uuid4())})
          def do_PUT(self):
              self.reply(200, self.body())
          def do_DELETE(self):
              self.reply(204)
          def log_message(self, *args):
              pass
      http.server.HTTPServer(("", 8080), Handler).serve_forever()
    ports:
    - containerPort: 8080
    readinessProbe:
      tcpSocket:
        port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  selector:
    app: %[1]s
  ports:
  - port: 8080
`, name, userNS))

	Eventually(func(g Gomega) {
		pod, err := getObject("pod", name, userNS)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(conditionField(pod, "Ready", "status")).To(Equal("True"))
	}).Should(Succeed())
}

// scimProvider is the part of Pocket-ID's SCIM provider the tests read.
type scimProvider struct {
	Endpoint     string `json:"endpoint"`
	LastSyncedAt string `json:"lastSyncedAt"`
}

// getSCIMProvider returns the client's SCIM provider, or the zero value when Pocket-ID has
// none. The raw request is used rather than the typed client so a 404 stays distinguishable
// from a transport failure.
func getSCIMProvider(oidcClientID string) scimProvider {
	GinkgoHelper()

	var provider scimProvider
	body, code := pocketIDRequest(http.MethodGet, "/api/admin/oidc/clients/"+oidcClientID+"/scim-service-provider")
	if code == http.StatusNotFound {
		return provider
	}
	Expect(code).To(Equal(http.StatusOK), "reading SCIM provider: %d: %s", code, body)
	Expect(json.Unmarshal([]byte(body), &provider)).To(Succeed(), "decoding SCIM provider")
	return provider
}

// getSCIMProviderEndpoint returns the client's SCIM endpoint, or "" when it has no provider.
func getSCIMProviderEndpoint(oidcClientID string) string {
	GinkgoHelper()
	return getSCIMProvider(oidcClientID).Endpoint
}

// checkSCIMProviderExists reports whether a SCIM service provider exists for the client.
func checkSCIMProviderExists(oidcClientID string) bool {
	GinkgoHelper()
	return getStatusFromPocketID("/api/admin/oidc/clients/"+oidcClientID+"/scim-service-provider") == http.StatusOK
}

// checkSCIMProviderGone reports whether the SCIM service provider for the given OIDC
// client is gone. It reads the client-scoped GET, which 404s when the provider (or the
// client) is missing; DELETE cannot be used because Pocket-ID always answers 204 there,
// whether or not the record existed.
func checkSCIMProviderGone(oidcClientID string) bool {
	GinkgoHelper()
	return getStatusFromPocketID("/api/admin/oidc/clients/"+oidcClientID+"/scim-service-provider") == http.StatusNotFound
}

// createSCIMProviderInPocketID creates a SCIM service provider directly in Pocket-ID and
// returns its ID.
func createSCIMProviderInPocketID(oidcClientID, endpoint string) string {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	provider, err := pid.Decode[pid.SCIMServiceProviderDTO](pocketID.CreateSCIMServiceProvider(ctx,
		pid.SCIMServiceProviderCreateDTO{OIDCClientID: oidcClientID, Endpoint: endpoint}))
	Expect(err).NotTo(HaveOccurred(), "creating SCIM provider for client %s", oidcClientID)
	Expect(provider.ID).NotTo(BeEmpty())
	return provider.ID
}
