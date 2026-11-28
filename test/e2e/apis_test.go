//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// permIDFromStatus returns the Pocket-ID permission ID that the operator resolved for a
// given permission key, read from the PocketIDAPI status. Waits until it is populated.
func permIDFromStatus(apiName, key string) string {
	return waitForStatusFieldNotEmpty("pocketidapi", apiName, userNS,
		fmt.Sprintf(".status.permissions[?(@.key=='%s')].id", key))
}

var _ = Describe("PocketIDAPI", Ordered, func() {
	// This block drives a single API through its full configuration surface and verifies
	// each change lands in Pocket-ID's database via a direct API read.
	const (
		apiName  = "orders-api"
		resource = "https://orders.e2e.example.com"
	)
	var apiID string

	BeforeAll(func() {
		By("creating a PocketIDAPI with a display name and two permissions")
		createAPIAndWaitReady(APIOptions{
			Name:     apiName,
			SpecName: "Orders API",
			Resource: resource,
			Permissions: []APIPermissionOption{
				{Key: "read:orders", Name: "Read orders", Description: "Read access to orders"},
				{Key: "write:orders", Name: "Write orders"},
			},
		})
		apiID = waitForStatusFieldNotEmpty("pocketidapi", apiName, userNS, ".status.apiID")
	})

	Context("Initial reconciliation", func() {
		It("should populate apiID and resource in status", func() {
			Expect(apiID).NotTo(BeEmpty())
			waitForStatusField("pocketidapi", apiName, userNS, ".status.resource", resource)
		})

		It("should resolve both permission IDs into status", func() {
			Expect(permIDFromStatus(apiName, "read:orders")).NotTo(BeEmpty())
			Expect(permIDFromStatus(apiName, "write:orders")).NotTo(BeEmpty())
		})

		It("should reflect the API, resource and permissions in Pocket-ID's database", func() {
			body := getFromPocketID("/api/admin/apis/" + apiID)
			Expect(body).To(ContainSubstring(resource))
			Expect(body).To(ContainSubstring("Orders API"))
			Expect(body).To(ContainSubstring("read:orders"))
			Expect(body).To(ContainSubstring("Read access to orders"))
			Expect(body).To(ContainSubstring("write:orders"))
		})
	})

	Context("Sole ownership of permissions", func() {
		It("should add a permission when one is appended to spec", func() {
			By("appending a delete:orders permission")
			createAPI(APIOptions{
				Name: apiName, SpecName: "Orders API", Resource: resource,
				Permissions: []APIPermissionOption{
					{Key: "read:orders", Name: "Read orders", Description: "Read access to orders"},
					{Key: "write:orders", Name: "Write orders"},
					{Key: "delete:orders", Name: "Delete orders"},
				},
			})

			By("waiting for the new permission ID to appear in status")
			Eventually(func(g Gomega) {
				out := getField("pocketidapi", apiName, userNS, ".status.permissions[?(@.key=='delete:orders')].id")
				g.Expect(out).NotTo(BeEmpty())
			}).Should(Succeed())

			By("confirming Pocket-ID's database contains the new permission")
			body := getFromPocketID("/api/admin/apis/" + apiID)
			Expect(body).To(ContainSubstring("delete:orders"))
		})

		It("should remove a permission when it is dropped from spec", func() {
			By("dropping delete:orders from spec")
			createAPI(APIOptions{
				Name: apiName, SpecName: "Orders API", Resource: resource,
				Permissions: []APIPermissionOption{
					{Key: "read:orders", Name: "Read orders", Description: "Read access to orders"},
					{Key: "write:orders", Name: "Write orders"},
				},
			})

			By("waiting for the dropped permission to leave status")
			Eventually(func(g Gomega) {
				out := getField("pocketidapi", apiName, userNS, ".status.permissions[?(@.key=='delete:orders')].id")
				g.Expect(out).To(BeEmpty())
			}).Should(Succeed())

			By("confirming Pocket-ID's database no longer contains the permission")
			body := getFromPocketID("/api/admin/apis/" + apiID)
			Expect(body).NotTo(ContainSubstring("delete:orders"))
			Expect(body).To(ContainSubstring("read:orders"))
			Expect(body).To(ContainSubstring("write:orders"))
		})

		It("should update a permission's display fields in place, keeping its ID", func() {
			originalID := permIDFromStatus(apiName, "write:orders")

			By("renaming the write:orders permission and adding a description")
			createAPI(APIOptions{
				Name: apiName, SpecName: "Orders API", Resource: resource,
				Permissions: []APIPermissionOption{
					{Key: "read:orders", Name: "Read orders", Description: "Read access to orders"},
					{Key: "write:orders", Name: "Write and modify orders", Description: "Write access"},
				},
			})

			By("waiting for the new display name to reflect in status")
			Eventually(func(g Gomega) {
				out := getField("pocketidapi", apiName, userNS, ".status.permissions[?(@.key=='write:orders')].name")
				g.Expect(out).To(Equal("Write and modify orders"))
			}).Should(Succeed())

			By("verifying the permission ID is unchanged (updated in place, not recreated)")
			Expect(permIDFromStatus(apiName, "write:orders")).To(Equal(originalID))

			By("confirming Pocket-ID's database reflects the new display fields")
			body := getFromPocketID("/api/admin/apis/" + apiID)
			Expect(body).To(ContainSubstring("Write and modify orders"))
		})
	})

	Context("Name update", func() {
		It("should rename the API in Pocket-ID while keeping resource and apiID", func() {
			By("changing spec.name")
			createAPI(APIOptions{
				Name: apiName, SpecName: "Orders API Renamed", Resource: resource,
				Permissions: []APIPermissionOption{
					{Key: "read:orders", Name: "Read orders", Description: "Read access to orders"},
					{Key: "write:orders", Name: "Write and modify orders", Description: "Write access"},
				},
			})

			By("waiting for the new name in status")
			waitForStatusField("pocketidapi", apiName, userNS, ".status.name", "Orders API Renamed")

			By("verifying the apiID and resource are unchanged")
			Expect(getField("pocketidapi", apiName, userNS, ".status.apiID")).To(Equal(apiID))
			Expect(getField("pocketidapi", apiName, userNS, ".status.resource")).To(Equal(resource))

			By("confirming Pocket-ID's database reflects the rename")
			body := getFromPocketID("/api/admin/apis/" + apiID)
			Expect(body).To(ContainSubstring("Orders API Renamed"))
			Expect(body).To(ContainSubstring(resource))
		})
	})
})

var _ = Describe("PocketIDAPI defaulting", Ordered, func() {
	It("should use metadata.name as the Pocket-ID name when spec.name is omitted", func() {
		const apiName = "defaulted-api"
		const resource = "https://defaulted.e2e.example.com"

		createAPIAndWaitReady(APIOptions{
			Name:     apiName,
			Resource: resource,
			// SpecName intentionally omitted
			Permissions: []APIPermissionOption{{Key: "read:default", Name: "Read"}},
		})

		waitForStatusField("pocketidapi", apiName, userNS, ".status.name", apiName)

		apiID := waitForStatusFieldNotEmpty("pocketidapi", apiName, userNS, ".status.apiID")
		body := getFromPocketID("/api/admin/apis/" + apiID)
		Expect(body).To(ContainSubstring(apiName))
		Expect(body).To(ContainSubstring(resource))
	})
})

var _ = Describe("PocketIDAPI Client Access", Ordered, func() {
	// Verifies that OIDCClient.spec.apiAccess resolves permission keys to IDs and that the
	// user-delegated / client-credentials split lands correctly in Pocket-ID's database.
	const (
		apiName    = "access-api"
		resource   = "https://access.e2e.example.com"
		clientName = "access-client"
	)
	var readID, syncID, clientID string

	BeforeAll(func() {
		By("creating an API with a read (delegated) and a sync (M2M) permission")
		createAPIAndWaitReady(APIOptions{
			Name: apiName, SpecName: "Access API", Resource: resource,
			Permissions: []APIPermissionOption{
				{Key: "read:data", Name: "Read data"},
				{Key: "sync:data", Name: "Sync data"},
			},
		})
		readID = permIDFromStatus(apiName, "read:data")
		syncID = permIDFromStatus(apiName, "sync:data")

		By("creating a confidential OIDC client granting delegated + client permissions")
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://access.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{{
				APIRefName:           apiName,
				DelegatedPermissions: []string{"read:data"},
				ClientPermissions:    []string{"sync:data"},
			}},
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
	})

	It("should reflect the delegated/client split in Pocket-ID's database", func() {
		// Eventually because the wait that got here is waitForReady, which does not gate on
		// observedGeneration: Ready can still be the previous generation's.
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			// read:data was granted for the user-delegated flow, sync:data for client-credentials.
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"userDelegatedPermissionIds":["%s"]`, readID)))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"clientPermissionIds":["%s"]`, syncID)))
			g.Expect(body).To(ContainSubstring(`"userDelegatedAccess":true`))
			g.Expect(body).To(ContainSubstring(`"clientAccess":true`))
		}).Should(Succeed())
	})

	It("should publish the resource and client scopes in the credentials Secret", func() {
		secret := clientName + "-oidc-credentials"
		Eventually(func(g Gomega) {
			// One API, so the bare pair is written alongside the per-API pair.
			g.Expect(secretData(secret, userNS, "resource")).To(Equal(resource))
			// Only sync:data is a client-credentials permission.
			g.Expect(secretData(secret, userNS, "scopes")).To(Equal("sync:data"))
			g.Expect(secretData(secret, userNS, "resource_"+apiName)).To(Equal(resource))
			g.Expect(secretData(secret, userNS, "scopes_"+apiName)).To(Equal("sync:data"))
		}).Should(Succeed())
	})

	It("should update access in Pocket-ID when the grant changes", func() {
		By("moving sync:data into the delegated flow alongside read:data")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://access.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{{
				APIRefName:           apiName,
				DelegatedPermissions: []string{"read:data", "sync:data"},
			}},
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		By("verifying Pocket-ID moved sync:data to the delegated bucket and cleared client permissions")
		// A bare read on purpose: waitForReconciled gates on observedGeneration, so this
		// asserts that Ready for a generation means that generation reached Pocket-ID.
		body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
		// clientPermissionIds empty + both IDs present proves both are now user-delegated.
		Expect(body).To(ContainSubstring(`"clientPermissionIds":[]`))
		Expect(body).To(ContainSubstring(`"clientAccess":false`))
		Expect(body).To(ContainSubstring(readID))
		Expect(body).To(ContainSubstring(syncID))
	})

	It("should clear access in Pocket-ID when apiAccess is emptied", func() {
		By("removing apiAccess from the client")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://access.e2e.example.com/callback"},
			// APIAccess intentionally absent
		})
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("confirming the credentials Secret dropped the resource and scopes keys")
		Eventually(func(g Gomega) {
			g.Expect(secretData(clientName+"-oidc-credentials", userNS, "resource")).To(BeEmpty())
			g.Expect(secretData(clientName+"-oidc-credentials", userNS, "scopes")).To(BeEmpty())
		}).Should(Succeed())

		By("confirming Pocket-ID's database has no access for the client")
		// Eventually because the wait that got here is waitForReady, which does not gate on
		// observedGeneration: Ready can still be the previous generation's.
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			g.Expect(body).NotTo(ContainSubstring(readID))
			g.Expect(body).NotTo(ContainSubstring(syncID))
		}).Should(Succeed())
	})

	cleanupAfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		_ = deleteObjectAndWait("pocketidapi", apiName, userNS, time.Minute)
	})
})

var _ = Describe("PocketIDAPI CIMD Access", Ordered, func() {
	// spec.cimdAccess grants every client registered through a Client ID Metadata Document
	// access to the API, so dynamically-registered clients need no individual grant.
	const (
		apiName  = "cimd-access-api"
		resource = "https://cimd-access.e2e.example.com"
	)
	var apiID, readID string

	BeforeAll(func() {
		createAPIAndWaitReady(APIOptions{
			Name: apiName, Resource: resource,
			Permissions: []APIPermissionOption{
				{Key: "read:data", Name: "Read data", CIMDAccess: true},
				{Key: "write:data", Name: "Write data"},
			},
		})
		apiID = waitForStatusFieldNotEmpty("pocketidapi", apiName, userNS, ".status.apiID")
		readID = permIDFromStatus(apiName, "read:data")
	})

	It("should enable CIMD access from the permission mark alone", func() {
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/apis/" + apiID)
			g.Expect(body).To(ContainSubstring(`"allowCimdClients":true`))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"read:data","name":"Read data","allowedForCimdClients":true`, readID)))
			g.Expect(body).To(ContainSubstring(`"key":"write:data","name":"Write data"`))
			g.Expect(body).NotTo(ContainSubstring(`"key":"write:data","name":"Write data","allowedForCimdClients":true`))
		}).Should(Succeed())
	})

	It("should mirror the resolved state into status", func() {
		waitForStatusField("pocketidapi", apiName, userNS, ".status.cimdAccess", "true")
	})

	// A permission added in the same edit that grants it has no ID until Pocket-ID creates
	// it, so this only works if the CIMD push runs after the permission update.
	It("should grant a permission added in the same edit as the grant", func() {
		createAPI(APIOptions{
			Name: apiName, Resource: resource,
			Permissions: []APIPermissionOption{
				{Key: "read:data", Name: "Read data", CIMDAccess: true},
				{Key: "write:data", Name: "Write data"},
				{Key: "sync:data", Name: "Sync data", CIMDAccess: true},
			},
		})
		waitForReconciled("pocketidapi", apiName, userNS)

		Eventually(func(g Gomega) {
			syncID := permIDFromStatus(apiName, "sync:data")
			body := getFromPocketID("/api/admin/apis/" + apiID)
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"sync:data","name":"Sync data","allowedForCimdClients":true`, syncID)))
		}).Should(Succeed())
	})

	// The one row of the spec.cimdAccess table with no coverage, and the only one where the
	// operator's desired state is not directly observable: it pushes the marks while access is
	// off, so if it also diffed them it would re-push on every resync against a Pocket-ID that
	// clears them. Nothing in status or in Pocket-ID would look wrong while that happened.
	It("should turn access off explicitly while the marks stay in spec", func() {
		createAPI(APIOptions{
			Name: apiName, Resource: resource,
			Permissions: []APIPermissionOption{
				{Key: "read:data", Name: "Read data", CIMDAccess: true},
				{Key: "write:data", Name: "Write data"},
				{Key: "sync:data", Name: "Sync data", CIMDAccess: true},
			},
			CIMDAccess: new(false),
		})
		waitForReconciled("pocketidapi", apiName, userNS)

		By("verifying Pocket-ID revoked access despite the marks")
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/apis/" + apiID)
			g.Expect(body).NotTo(ContainSubstring(`"allowCimdClients":true`))
		}).Should(Succeed())
		waitForStatusField("pocketidapi", apiName, userNS, ".status.cimdAccess", "false")

		By("letting several reconciles pass and confirming the state stopped moving")
		before := getFromPocketID("/api/admin/apis/" + apiID)
		time.Sleep(30 * time.Second)
		after := getFromPocketID("/api/admin/apis/" + apiID)
		Expect(after).To(Equal(before),
			"an API with cimdAccess false and marked permissions must reach a stable state")
		waitForReady("pocketidapi", apiName, userNS)
	})

	// What "marks kept so it can be turned back on" has to mean in practice.
	It("should restore exactly the marked permissions when access is turned back on", func() {
		createAPI(APIOptions{
			Name: apiName, Resource: resource,
			Permissions: []APIPermissionOption{
				{Key: "read:data", Name: "Read data", CIMDAccess: true},
				{Key: "write:data", Name: "Write data"},
				{Key: "sync:data", Name: "Sync data", CIMDAccess: true},
			},
			// cimdAccess unset again: it derives back to true from the marks.
		})
		waitForReconciled("pocketidapi", apiName, userNS)

		Eventually(func(g Gomega) {
			syncID := permIDFromStatus(apiName, "sync:data")
			body := getFromPocketID("/api/admin/apis/" + apiID)
			g.Expect(body).To(ContainSubstring(`"allowCimdClients":true`))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"read:data","name":"Read data","allowedForCimdClients":true`, readID)))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"sync:data","name":"Sync data","allowedForCimdClients":true`, syncID)))
			g.Expect(body).NotTo(ContainSubstring(`"key":"write:data","name":"Write data","allowedForCimdClients":true`))
		}).Should(Succeed())
	})

	It("should disable CIMD access when the marks are removed", func() {
		createAPI(APIOptions{
			Name: apiName, Resource: resource,
			Permissions: []APIPermissionOption{
				{Key: "read:data", Name: "Read data"},
				{Key: "write:data", Name: "Write data"},
				{Key: "sync:data", Name: "Sync data"},
			},
			// No permission marked and no explicit flag: the operator turns access off.
		})
		waitForReconciled("pocketidapi", apiName, userNS)

		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/apis/" + apiID)
			g.Expect(body).NotTo(ContainSubstring(`"allowCimdClients":true`))
			g.Expect(body).NotTo(ContainSubstring(`"allowedForCimdClients":true`))
		}).Should(Succeed())
	})

	cleanupAfterAll(func() {
		_ = deleteObjectAndWait("pocketidapi", apiName, userNS, time.Minute)
	})
})

var _ = Describe("PocketIDAPI Scopeless Client Grant", Ordered, func() {
	// A client may be granted a resource without any scopes, which is what the MCP spec
	// expects. The grant exists even though no permission is selected.
	const (
		apiName    = "scopeless-api"
		resource   = "https://scopeless.e2e.example.com"
		clientName = "scopeless-client"
	)
	var clientID string

	BeforeAll(func() {
		createAPIAndWaitReady(APIOptions{
			Name: apiName, Resource: resource,
			Permissions: []APIPermissionOption{{Key: "read:data", Name: "Read data"}},
		})
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://scopeless.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{{
				APIRefName:      apiName,
				DelegatedAccess: new(true),
			}},
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
	})

	It("should grant delegated access with no permissions", func() {
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			g.Expect(body).To(ContainSubstring(`"userDelegatedAccess":true`))
			g.Expect(body).To(ContainSubstring(`"userDelegatedPermissionIds":[]`))
		}).Should(Succeed())
	})

	It("should grant the client-credentials flow with no permissions", func() {
		By("switching the scopeless grant from the delegated flow to client credentials")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://scopeless.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{{
				APIRefName:   apiName,
				ClientAccess: new(true),
			}},
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			g.Expect(body).To(ContainSubstring(`"clientAccess":true`))
			g.Expect(body).To(ContainSubstring(`"clientPermissionIds":[]`))
			g.Expect(body).To(ContainSubstring(`"userDelegatedAccess":false`))
		}).Should(Succeed())
	})

	// A scopeless grant is the case where desired and stored state are thinnest, so a grant
	// Pocket-ID stores differently from the request would show up as a changing grant.
	It("should settle on a stable grant", func() {
		before := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
		time.Sleep(30 * time.Second)
		after := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
		Expect(after).To(Equal(before), "a scopeless grant must reach a stable state")
		waitForReady("pocketidoidcclient", clientName, userNS)
	})

	It("should revoke the scopeless grant when the entry is removed", func() {
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://scopeless.e2e.example.com/callback"},
			// APIAccess intentionally absent
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			g.Expect(body).NotTo(ContainSubstring(`"clientAccess":true`))
			g.Expect(body).NotTo(ContainSubstring(`"userDelegatedAccess":true`))
		}).Should(Succeed())
	})

	cleanupAfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		_ = deleteObjectAndWait("pocketidapi", apiName, userNS, time.Minute)
	})
})

var _ = Describe("PocketIDAPI Multi-API Grants", Ordered, func() {
	// Access is stored per API, so dropping one apiAccess entry has to revoke that API alone.
	// A single-API client cannot tell a correct per-API revoke from one that clears everything.
	const (
		clientName  = "multi-api-client"
		ordersName  = "multi-orders-api"
		ordersRes   = "https://multi-orders.e2e.example.com"
		billingName = "multi-billing-api"
		billingRes  = "https://multi-billing.e2e.example.com"
	)
	var clientID, billingID, ordersPermID, billingPermID, appURL string
	secret := clientName + "-oidc-credentials"

	// builtInToken requests a client-credentials token with the Secret's built-in API pair.
	builtInToken := func() string {
		GinkgoHelper()
		token, errCode := clientCredentialsToken(secretData(secret, userNS, "client_id"), secretData(secret, userNS, "client_secret"), url.Values{
			"resource": {secretData(secret, userNS, "resource_pocket_id")},
			"scope":    {secretData(secret, userNS, "scopes_pocket_id")},
		})
		Expect(errCode).To(BeEmpty())
		return token
	}
	builtInGrants := func(scopes ...string) []APIAccessGrant {
		return []APIAccessGrant{
			{APIRefName: ordersName, DelegatedPermissions: []string{"read:orders"}},
			{APIRefName: billingName, ClientPermissions: []string{"read:billing"}},
			{BuiltIn: true, ClientPermissions: scopes},
		}
	}

	BeforeAll(func() {
		By("creating two APIs and a client granted access to both and to the built-in API")
		createAPIAndWaitReady(APIOptions{
			Name: ordersName, Resource: ordersRes,
			Permissions: []APIPermissionOption{{Key: "read:orders", Name: "Read orders"}},
		})
		createAPIAndWaitReady(APIOptions{
			Name: billingName, Resource: billingRes,
			Permissions: []APIPermissionOption{{Key: "read:billing", Name: "Read billing"}},
		})
		billingID = waitForStatusFieldNotEmpty("pocketidapi", billingName, userNS, ".status.apiID")
		ordersPermID = permIDFromStatus(ordersName, "read:orders")
		billingPermID = permIDFromStatus(billingName, "read:billing")

		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://multi.e2e.example.com/callback"},
			APIAccess:    builtInGrants("users:read"),
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
		appURL = getField("pocketidinstance", instanceName, instanceNS, ".spec.appUrl")
	})

	It("should grant every API independently", func() {
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"userDelegatedPermissionIds":["%s"]`, ordersPermID)))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"clientPermissionIds":["%s"]`, billingPermID)))
			g.Expect(body).To(ContainSubstring(pocketid.BuiltInAPIID))
		}).Should(Succeed())
	})

	It("should publish a resource and scopes pair per API in the credentials Secret", func() {
		Eventually(func(g Gomega) {
			g.Expect(secretData(secret, userNS, "resource_"+ordersName)).To(Equal(ordersRes))
			g.Expect(secretData(secret, userNS, "resource_"+billingName)).To(Equal(billingRes))
			// Only billing has a client-credentials permission.
			g.Expect(secretData(secret, userNS, "scopes_"+ordersName)).To(BeEmpty())
			g.Expect(secretData(secret, userNS, "scopes_"+billingName)).To(Equal("read:billing"))
			g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.builtInAPIResource")).To(Equal(appURL + "/api"))
			g.Expect(secretData(secret, userNS, "resource_pocket_id")).To(Equal(appURL + "/api"))
			g.Expect(secretData(secret, userNS, "scopes_pocket_id")).To(Equal("users:read"))
			// Several audiences, so the bare pair is left out.
			g.Expect(secretData(secret, userNS, "resource")).To(BeEmpty())
			g.Expect(secretData(secret, userNS, "scopes")).To(BeEmpty())
		}).Should(Succeed())

		By("calling Pocket ID's admin API with a token for the built-in API's pair")
		token := builtInToken()
		Expect(pocketIDStatusForBearer(token, "/api/admin/users")).To(Equal(http.StatusOK))
		Expect(pocketIDStatusForBearer(token, "/api/admin/user-groups")).To(Equal(http.StatusForbidden), "the token holds only users:read")
	})

	// After the first grant, the built-in API's permission IDs come from the client's grant
	// listing instead of a fetch of the API, so a later change exercises that path.
	It("should follow later changes to the built-in grant", func() {
		By("adding groups:read")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://multi.e2e.example.com/callback"},
			APIAccess:    builtInGrants("users:read", "groups:read"),
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)
		Eventually(func(g Gomega) {
			g.Expect(secretData(secret, userNS, "scopes_pocket_id")).To(Equal("groups:read users:read"))
		}).Should(Succeed())
		Expect(pocketIDStatusForBearer(builtInToken(), "/api/admin/user-groups")).To(Equal(http.StatusOK))

		// Pocket-ID drops it from the grant, so the Secret's scopes would be refused at the
		// token endpoint.
		By("listing an account scope, which the client-credentials flow can't hold")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://multi.e2e.example.com/callback"},
			APIAccess:    builtInGrants("users:read", "account:read"),
		})
		waitForConditionReason("pocketidoidcclient", clientName, userNS, "Ready", "APIAccessReconcileError")

		By("restoring the grant")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://multi.e2e.example.com/callback"},
			APIAccess:    builtInGrants("users:read"),
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)
	})

	It("should revoke only the dropped API and leave the other grant intact", func() {
		By("dropping the billing and built-in entries and keeping orders")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://multi.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{
				{APIRefName: ordersName, DelegatedPermissions: []string{"read:orders"}},
			},
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			g.Expect(body).NotTo(ContainSubstring(billingPermID),
				"the dropped API's grant should be gone")
			g.Expect(body).NotTo(ContainSubstring(pocketid.BuiltInAPIID),
				"the dropped built-in grant should be gone")
			g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.builtInAPIResource")).To(BeEmpty())
			g.Expect(body).To(ContainSubstring(ordersPermID),
				"the surviving entry must not be collateral damage")
		}).Should(Succeed())

		By("verifying the credentials Secret dropped the billing keys and regained the bare pair")
		Eventually(func(g Gomega) {
			g.Expect(secretData(secret, userNS, "resource_"+billingName)).To(BeEmpty())
			g.Expect(secretData(secret, userNS, "scopes_"+billingName)).To(BeEmpty())
			g.Expect(secretData(secret, userNS, "resource_"+ordersName)).To(Equal(ordersRes))
			// One audience again, so the bare resource comes back.
			g.Expect(secretData(secret, userNS, "resource")).To(Equal(ordersRes))
		}).Should(Succeed())
	})

	// The operator owns every grant the client holds, so access granted in the UI is revoked.
	It("should revoke access granted outside the operator", func() {
		grantAPIAccessInPocketID(billingID, clientID, billingPermID)
		grantAPIAccessInPocketID(pocketid.BuiltInAPIID, clientID)
		Expect(getFromPocketID("/api/admin/api-access/" + clientID + "/apis")).To(ContainSubstring(billingPermID))

		Expect(annotateObject("pocketidoidcclient", clientName, userNS, "test/trigger=ui-grant")).To(Succeed())

		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/admin/api-access/" + clientID + "/apis")
			g.Expect(body).NotTo(ContainSubstring(billingPermID), "the grant made in the UI should be revoked")
			g.Expect(body).To(ContainSubstring(ordersPermID), "the spec's grant must stay")
			g.Expect(body).NotTo(ContainSubstring(pocketid.BuiltInAPIID), "the built-in grant made in the UI should be revoked")
		}).Should(Succeed())
	})

	cleanupAfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		_ = deleteObjectAndWait("pocketidapi", ordersName, userNS, time.Minute)
		_ = deleteObjectAndWait("pocketidapi", billingName, userNS, time.Minute)
	})
})

var _ = Describe("PocketIDAPI Reference Finalizer", Ordered, func() {
	const (
		apiName    = "finalizer-api"
		resource   = "https://finalizer.e2e.example.com"
		clientName = "finalizer-api-client"
	)

	It("should block API deletion while referenced, and unblock when the grant is dropped", func() {
		By("creating an API and a client that grants access to it")
		createAPIAndWaitReady(APIOptions{
			Name: apiName, SpecName: "Finalizer API", Resource: resource,
			Permissions: []APIPermissionOption{{Key: "read:fin", Name: "Read"}},
		})
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://finalizer.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{{
				APIRefName:           apiName,
				DelegatedPermissions: []string{"read:fin"},
			}},
		})

		By("requesting deletion of the API")
		deleteObject("pocketidapi", apiName, userNS)

		By("verifying deletion is blocked by the reference finalizer")
		Eventually(func(g Gomega) {
			ts := getField("pocketidapi", apiName, userNS, ".metadata.deletionTimestamp")
			fin := getField("pocketidapi", apiName, userNS, ".metadata.finalizers")
			g.Expect(ts).NotTo(BeEmpty())
			g.Expect(fin).To(ContainSubstring("pocketid.internal/oidc-client-api-finalizer"))
		}).Should(Succeed())

		By("dropping the apiAccess grant from the client (edit-away, not client deletion)")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://finalizer.e2e.example.com/callback"},
			// APIAccess intentionally absent
		})
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("verifying the API is unblocked and deleted promptly")
		waitForResourceDeleted("pocketidapi", apiName, userNS)
	})

	cleanupAfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
	})
})

var _ = Describe("PocketIDAPI External Deletion Recovery", Ordered, func() {
	const (
		apiName  = "external-delete-api"
		resource = "https://ext-delete.e2e.example.com"
	)

	It("should recreate the API after external deletion from Pocket-ID", func() {
		createAPIAndWaitReady(APIOptions{
			Name: apiName, SpecName: "Ext Delete API", Resource: resource,
			Permissions: []APIPermissionOption{{Key: "read:ext", Name: "Read"}},
		})
		originalAPIID := waitForStatusFieldNotEmpty("pocketidapi", apiName, userNS, ".status.apiID")

		By("deleting the API directly from Pocket-ID")
		deleteFromPocketID("/api/admin/apis/" + originalAPIID)

		By("waiting for the operator to detect deletion and recreate with a new ID")
		Eventually(func(g Gomega) {
			newID := getField("pocketidapi", apiName, userNS, ".status.apiID")
			g.Expect(newID).NotTo(BeEmpty())
			g.Expect(newID).NotTo(Equal(originalAPIID), "API should have a new ID after recreation")
		}).Should(Succeed())

		By("verifying the API is Ready and its permission is restored")
		waitForReady("pocketidapi", apiName, userNS)
		Expect(permIDFromStatus(apiName, "read:ext")).NotTo(BeEmpty())
	})

	cleanupAfterAll(func() {
		_ = deleteObjectAndWait("pocketidapi", apiName, userNS, time.Minute)
	})
})

var _ = Describe("PocketIDAPI Adoption", Ordered, func() {
	const (
		apiName  = "adopt-api"
		resource = "https://adopt.e2e.example.com"
	)

	It("should adopt a pre-existing API matched by resource and take ownership", func() {
		By("creating an API directly in Pocket-ID (simulating the UI)")
		existingID := createAPIInPocketID("Pre-created API", resource)
		Expect(existingID).NotTo(BeEmpty())

		By("creating a PocketIDAPI with the same resource")
		createAPIAndWaitReady(APIOptions{
			Name: apiName, SpecName: "Adopted API", Resource: resource,
			Permissions: []APIPermissionOption{{Key: "read:adopt", Name: "Read"}},
		})

		By("verifying the operator adopted the existing record (same ID, never recreated)")
		waitForStatusField("pocketidapi", apiName, userNS, ".status.apiID", existingID)

		By("verifying sole ownership applied the spec name and permissions to the adopted API")
		waitForStatusField("pocketidapi", apiName, userNS, ".status.name", "Adopted API")
		Expect(permIDFromStatus(apiName, "read:adopt")).NotTo(BeEmpty())

		body := getFromPocketID("/api/admin/apis/" + existingID)
		Expect(body).To(ContainSubstring("Adopted API"))
		Expect(body).To(ContainSubstring("read:adopt"))
	})

	It("should not adopt the built-in Pocket ID API", func() {
		const builtInName = "builtin-api"
		appURL := getField("pocketidinstance", instanceName, instanceNS, ".spec.appUrl")
		createAPI(APIOptions{Name: builtInName, Resource: appURL + "/api"})

		By("verifying Pocket-ID rejects the reserved resource and nothing was adopted")
		waitForConditionReason("pocketidapi", builtInName, userNS, "Ready", "ReconcileError")
		Expect(getField("pocketidapi", builtInName, userNS, ".status.apiID")).To(BeEmpty())

		Expect(deleteObjectAndWait("pocketidapi", builtInName, userNS, time.Minute)).To(Succeed())
	})

	cleanupAfterAll(func() {
		_ = deleteObjectAndWait("pocketidapi", apiName, userNS, time.Minute)
	})
})

// Serial because the built-in API's CIMD access reaches every CIMD client, and the CIMD specs
// assert exactly which APIs their clients reach.
var _ = Describe("Built-in Pocket ID API CIMD Access", Serial, Ordered, func() {
	const clientName = "builtin-cimd-client"
	var builtInResource string

	setBuiltInAPI := func(value string) {
		GinkgoHelper()
		Expect(patchObject("pocketidinstance", instanceName, instanceNS, `{"spec":{"builtInAPI":`+value+`}}`)).To(Succeed())
	}
	cimdAccess := func(g Gomega) (bool, []string) {
		ctx, cancel := testCtx()
		defer cancel()
		api, err := pid.Decode[pid.APIResponseDto](pocketID.GetAPIByID(ctx, pocketid.BuiltInAPIID))
		g.Expect(err).NotTo(HaveOccurred())
		var keys []string
		for _, p := range api.Permissions {
			if p.AllowedForCIMDClients {
				keys = append(keys, p.Key)
			}
		}
		return api.AllowCIMDClients, keys
	}
	cimdGrantedAPIs := func() string {
		return getField("pocketidoidcclient", clientName, userNS, ".status.cimdGrantedAPIs[*]")
	}
	clientGrants := func() string {
		return getFromPocketID("/api/admin/api-access/" + encodeCIMDClientID(cimdMetadataURL) + "/apis")
	}

	BeforeAll(func() {
		builtInResource = getField("pocketidinstance", instanceName, instanceNS, ".spec.appUrl") + "/api"
		requireCIMDDocumentReachable()
		materializeCIMDClient()
		createOIDCClient(OIDCClientOptions{Name: clientName, ClientID: cimdMetadataURL})
		waitForReady("pocketidoidcclient", clientName, userNS)
	})

	It("should let every CIMD client request the listed permissions", func() {
		setBuiltInAPI(`{"cimdPermissions":["users:read"]}`)
		Eventually(func(g Gomega) {
			enabled, keys := cimdAccess(g)
			g.Expect(enabled).To(BeTrue())
			g.Expect(keys).To(ConsistOf("users:read"))
		}).Should(Succeed())

		By("verifying the CIMD client reports the built-in API and keeps it")
		Eventually(func(g Gomega) {
			g.Expect(cimdGrantedAPIs()).To(Equal(builtInResource))
		}).Should(Succeed())
		waitForReady("pocketidoidcclient", clientName, userNS)
	})

	It("should grant a CIMD client the built-in API through apiAccess", func() {
		createOIDCClient(OIDCClientOptions{
			Name:      clientName,
			ClientID:  cimdMetadataURL,
			APIAccess: []APIAccessGrant{{BuiltIn: true, DelegatedPermissions: []string{"users:read"}}},
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)
		Expect(clientGrants()).To(ContainSubstring(`"userDelegatedAccess":true`))

		By("dropping the entry, which revokes the grant but not the CIMD access")
		createOIDCClient(OIDCClientOptions{Name: clientName, ClientID: cimdMetadataURL})
		waitForReconciled("pocketidoidcclient", clientName, userNS)
		Eventually(func(g Gomega) {
			g.Expect(clientGrants()).NotTo(ContainSubstring(`"userDelegatedAccess":true`))
		}).Should(Succeed())
		Expect(cimdGrantedAPIs()).To(Equal(builtInResource))
	})

	It("should leave the setting alone once spec.builtInAPI is unset", func() {
		setBuiltInAPI(`null`)
		// Not waitForReconciled: an instance's Ready reason is "Ready", not "Reconciled".
		gen := getField("pocketidinstance", instanceName, instanceNS, ".metadata.generation")
		waitForStatusField("pocketidinstance", instanceName, instanceNS, ".status.conditions[?(@.type=='Ready')].observedGeneration", gen)
		Consistently(func(g Gomega) {
			enabled, keys := cimdAccess(g)
			g.Expect(enabled).To(BeTrue())
			g.Expect(keys).To(ConsistOf("users:read"))
		}, 10*time.Second, time.Second).Should(Succeed())
	})

	It("should turn the access off when no permissions are listed", func() {
		setBuiltInAPI(`{}`)
		Eventually(func(g Gomega) {
			enabled, keys := cimdAccess(g)
			g.Expect(enabled).To(BeFalse())
			g.Expect(keys).To(BeEmpty())
		}).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(cimdGrantedAPIs()).To(BeEmpty())
		}).Should(Succeed())
	})

	// Restores the shared instance even after a failure, so specs on it elsewhere don't fail too.
	AfterAll(func() {
		_ = patchObject("pocketidinstance", instanceName, instanceNS, `{"spec":{"builtInAPI":null}}`)
	})

	cleanupAfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})
