//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Logo Auto-Generation", Ordered, func() {
	// These tests verify that the operator correctly resolves logo URLs
	// and applies them to the OIDC client in Pocket-ID.
	// The e2e overlay disables auto-generation globally, so these tests
	// explicitly opt in via spec.logo.autoGenerate.

	Context("Auto-generated logos", func() {
		const clientName = "test-logo-autogen"

		It("should apply logos when autoGenerate is enabled with a known icon name", func() {
			By("creating an OIDC client with logo auto-generation enabled")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{
					AutoGenerate: boolPtr(true),
					NameOverride: "grafana",
				},
			}))

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the logo was applied in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Eventually(func(g Gomega) {
				hasLogo := getOIDCClientField(oidcClientID, "hasLogo")
				g.Expect(hasLogo).To(Equal("true"))
			}).Should(Succeed())

			By("verifying the applied logo URL is recorded in status")
			logoURL := getField("pocketidoidcclient", clientName, userNS, ".status.logoUrl")
			Expect(logoURL).To(ContainSubstring("grafana"))
		})

		It("should remove the logo it applied once the spec stops asking for one", func() {
			oidcClientID := getField("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("disabling auto-generation on the existing client")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{AutoGenerate: boolPtr(false)},
			}))

			By("verifying the logo is deleted from Pocket-ID and the applied record cleared")
			Eventually(func(g Gomega) {
				g.Expect(getOIDCClientField(oidcClientID, "hasLogo")).To(Equal("false"))
				g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.logoUrl")).To(BeEmpty())
			}).Should(Succeed())
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Auto-generation disabled", func() {
		const clientName = "test-logo-disabled"

		It("should not set logos when autoGenerate is false", func() {
			By("creating an OIDC client with logo auto-generation explicitly disabled")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{
					AutoGenerate: boolPtr(false),
				},
			}))

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying no logo was applied in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			hasLogo := getOIDCClientField(oidcClientID, "hasLogo")
			Expect(hasLogo).To(Equal("false"))
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	// Issue #603: a logo the operator never applied is not the operator's to manage, so it
	// must survive every resync untouched rather than driving an update that cannot converge.
	Context("Logo uploaded out of band", func() {
		const clientName = "test-logo-uploaded"

		It("should leave an uploaded logo alone when autoGenerate is false", func() {
			By("creating an OIDC client with logo auto-generation disabled")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{AutoGenerate: boolPtr(false)},
			}))
			waitForReady("pocketidoidcclient", clientName, userNS)
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("uploading a logo directly to Pocket-ID, as the UI would")
			uploadLogoToPocketID(oidcClientID, true)
			Expect(getOIDCClientField(oidcClientID, "hasLogo")).To(Equal("true"))

			By("forcing a reconcile and verifying the upload survives")
			Expect(annotateObject("pocketidoidcclient", clientName, userNS, "test/trigger-reconcile=1")).To(Succeed())
			Consistently(func(g Gomega) {
				g.Expect(getOIDCClientField(oidcClientID, "hasLogo")).To(Equal("true"))
				g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.logoUrl")).To(BeEmpty())
			}, 20*time.Second, 4*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// onePixelPNG is the smallest valid PNG, used as a stand-in for a logo a user uploaded.
var onePixelPNG = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00,
	0x1f, 0x15, 0xc4, 0x89,
	0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T',
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
	0x0d, 0x0a, 0x2d, 0xb4,
	0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

// uploadLogoToPocketID attaches a logo to a client the way the UI does — a multipart upload
// to the logo endpoint, leaving no logoUrl for the operator to have recorded as applied.
func uploadLogoToPocketID(oidcClientID string, light bool) {
	GinkgoHelper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "logo.png")
	Expect(err).NotTo(HaveOccurred(), "building multipart form")
	_, err = part.Write(onePixelPNG)
	Expect(err).NotTo(HaveOccurred(), "writing logo bytes")
	Expect(writer.Close()).To(Succeed())

	ctx, cancel := testCtx()
	defer cancel()

	apiPath := fmt.Sprintf("/api/oidc/clients/%s/logo?light=%t", oidcClientID, light)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pocketIDBaseURL()+apiPath, &buf)
	Expect(err).NotTo(HaveOccurred(), "building logo upload request")
	req.Header.Set("X-API-KEY", staticAPIKey())
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred(), "uploading logo")
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	Expect(resp.StatusCode).To(BeNumerically("<", 300), "POST %s returned %d: %s", apiPath, resp.StatusCode, body)
}

// getOIDCClientField returns one top-level field of an OIDC client as Pocket-ID reports
// it, rendered the way the previous shell version did: bare scalars, so a boolean reads
// as "true" and an absent field as "<nil>".
func getOIDCClientField(oidcClientID, field string) string {
	GinkgoHelper()

	body := getFromPocketID("/api/oidc/clients/" + oidcClientID)

	var client map[string]any
	Expect(json.Unmarshal([]byte(body), &client)).To(Succeed(), "decoding OIDC client")
	return fmt.Sprint(client[field])
}
