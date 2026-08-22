//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
			body := getFromPocketID("/api/apis/" + apiID)
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
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("confirming Pocket-ID's database contains the new permission")
			body := getFromPocketID("/api/apis/" + apiID)
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
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("confirming Pocket-ID's database no longer contains the permission")
			body := getFromPocketID("/api/apis/" + apiID)
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
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the permission ID is unchanged (updated in place, not recreated)")
			Expect(permIDFromStatus(apiName, "write:orders")).To(Equal(originalID))

			By("confirming Pocket-ID's database reflects the new display fields")
			body := getFromPocketID("/api/apis/" + apiID)
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
			body := getFromPocketID("/api/apis/" + apiID)
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
		body := getFromPocketID("/api/apis/" + apiID)
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

	It("should record the resolved permission IDs in the client status", func() {
		Eventually(func(g Gomega) {
			out := getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIPermissionIDs[*]")
			g.Expect(out).To(ContainSubstring(readID))
			g.Expect(out).To(ContainSubstring(syncID))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("should reflect the delegated/client split in Pocket-ID's database", func() {
		body := getFromPocketID("/api/api-access/" + clientID + "/apis")
		// read:data was granted for the user-delegated flow, sync:data for client-credentials.
		Expect(body).To(ContainSubstring(fmt.Sprintf(`"userDelegatedPermissionIds":["%s"]`, readID)))
		Expect(body).To(ContainSubstring(fmt.Sprintf(`"clientPermissionIds":["%s"]`, syncID)))
		Expect(body).To(ContainSubstring(`"userDelegatedAccess":true`))
		Expect(body).To(ContainSubstring(`"clientAccess":true`))
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
		body := getFromPocketID("/api/api-access/" + clientID + "/apis")
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

		By("waiting for managed permission IDs to clear from status")
		Eventually(func(g Gomega) {
			out := getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIPermissionIDs[*]")
			g.Expect(out).To(BeEmpty())
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		By("confirming Pocket-ID's database has no access for the client")
		body := getFromPocketID("/api/api-access/" + clientID + "/apis")
		Expect(body).NotTo(ContainSubstring(readID))
		Expect(body).NotTo(ContainSubstring(syncID))
	})

	AfterAll(func() {
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
			body := getFromPocketID("/api/apis/" + apiID)
			g.Expect(body).To(ContainSubstring(`"allowCimdClients":true`))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"read:data","name":"Read data","allowedForCimdClients":true`, readID)))
			g.Expect(body).To(ContainSubstring(`"key":"write:data","name":"Write data"`))
			g.Expect(body).NotTo(ContainSubstring(`"key":"write:data","name":"Write data","allowedForCimdClients":true`))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
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
			body := getFromPocketID("/api/apis/" + apiID)
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"sync:data","name":"Sync data","allowedForCimdClients":true`, syncID)))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
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
			CIMDAccess: boolPtr(false),
		})
		waitForReconciled("pocketidapi", apiName, userNS)

		By("verifying Pocket-ID revoked access despite the marks")
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/apis/" + apiID)
			g.Expect(body).NotTo(ContainSubstring(`"allowCimdClients":true`))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
		waitForStatusField("pocketidapi", apiName, userNS, ".status.cimdAccess", "false")

		By("letting several reconciles pass and confirming the state stopped moving")
		before := getFromPocketID("/api/apis/" + apiID)
		time.Sleep(30 * time.Second)
		after := getFromPocketID("/api/apis/" + apiID)
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
			body := getFromPocketID("/api/apis/" + apiID)
			g.Expect(body).To(ContainSubstring(`"allowCimdClients":true`))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"read:data","name":"Read data","allowedForCimdClients":true`, readID)))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"id":"%s","key":"sync:data","name":"Sync data","allowedForCimdClients":true`, syncID)))
			g.Expect(body).NotTo(ContainSubstring(`"key":"write:data","name":"Write data","allowedForCimdClients":true`))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
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
			body := getFromPocketID("/api/apis/" + apiID)
			g.Expect(body).NotTo(ContainSubstring(`"allowCimdClients":true`))
			g.Expect(body).NotTo(ContainSubstring(`"allowedForCimdClients":true`))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	AfterAll(func() {
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
				DelegatedAccess: boolPtr(true),
			}},
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
	})

	It("should grant delegated access with no permissions", func() {
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/api-access/" + clientID + "/apis")
			g.Expect(body).To(ContainSubstring(`"userDelegatedAccess":true`))
			g.Expect(body).To(ContainSubstring(`"userDelegatedPermissionIds":[]`))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	// A scopeless grant carries no permission IDs, so status.managedAPIs is the only record
	// that the operator granted anything and the only thing that can revoke it later.
	It("should record the API in status even though no permission was resolved", func() {
		apiID := waitForStatusFieldNotEmpty("pocketidapi", apiName, userNS, ".status.apiID")
		Eventually(func(g Gomega) {
			g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIs[*]")).To(Equal(apiID))
			g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIPermissionIDs[*]")).To(BeEmpty())
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("should grant the client-credentials flow with no permissions", func() {
		By("switching the scopeless grant from the delegated flow to client credentials")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://scopeless.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{{
				APIRefName:   apiName,
				ClientAccess: boolPtr(true),
			}},
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/api-access/" + clientID + "/apis")
			g.Expect(body).To(ContainSubstring(`"clientAccess":true`))
			g.Expect(body).To(ContainSubstring(`"clientPermissionIds":[]`))
			g.Expect(body).To(ContainSubstring(`"userDelegatedAccess":false`))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	// A scopeless grant is the case where desired and observed state are thinnest, so a
	// mismatch the operator can never satisfy would show up as a silent re-push loop.
	It("should settle instead of re-pushing the grant", func() {
		before := getFromPocketID("/api/api-access/" + clientID + "/apis")
		time.Sleep(30 * time.Second)
		after := getFromPocketID("/api/api-access/" + clientID + "/apis")
		Expect(after).To(Equal(before), "a scopeless grant must reach a stable state")
		waitForReady("pocketidoidcclient", clientName, userNS)
	})

	It("should revoke the scopeless grant when the entry is removed", func() {
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://scopeless.e2e.example.com/callback"},
			// APIAccess intentionally absent: nothing but status.managedAPIs records the grant.
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		Eventually(func(g Gomega) {
			g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIs[*]")).To(BeEmpty())
			body := getFromPocketID("/api/api-access/" + clientID + "/apis")
			g.Expect(body).NotTo(ContainSubstring(`"clientAccess":true`))
			g.Expect(body).NotTo(ContainSubstring(`"userDelegatedAccess":true`))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	AfterAll(func() {
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
	var clientID, ordersID, billingID, ordersPermID, billingPermID string

	BeforeAll(func() {
		By("creating two APIs and a client granted access to both")
		createAPIAndWaitReady(APIOptions{
			Name: ordersName, Resource: ordersRes,
			Permissions: []APIPermissionOption{{Key: "read:orders", Name: "Read orders"}},
		})
		createAPIAndWaitReady(APIOptions{
			Name: billingName, Resource: billingRes,
			Permissions: []APIPermissionOption{{Key: "read:billing", Name: "Read billing"}},
		})
		ordersID = waitForStatusFieldNotEmpty("pocketidapi", ordersName, userNS, ".status.apiID")
		billingID = waitForStatusFieldNotEmpty("pocketidapi", billingName, userNS, ".status.apiID")
		ordersPermID = permIDFromStatus(ordersName, "read:orders")
		billingPermID = permIDFromStatus(billingName, "read:billing")

		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://multi.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{
				{APIRefName: ordersName, DelegatedPermissions: []string{"read:orders"}},
				{APIRefName: billingName, ClientPermissions: []string{"read:billing"}},
			},
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
	})

	It("should grant both APIs independently", func() {
		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/api-access/" + clientID + "/apis")
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"userDelegatedPermissionIds":["%s"]`, ordersPermID)))
			g.Expect(body).To(ContainSubstring(fmt.Sprintf(`"clientPermissionIds":["%s"]`, billingPermID)))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		By("verifying status tracks both API IDs")
		Eventually(func(g Gomega) {
			out := getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIs[*]")
			g.Expect(out).To(ContainSubstring(ordersID))
			g.Expect(out).To(ContainSubstring(billingID))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("should revoke only the dropped API and leave the other grant intact", func() {
		By("dropping the billing entry and keeping orders")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://multi.e2e.example.com/callback"},
			APIAccess: []APIAccessGrant{
				{APIRefName: ordersName, DelegatedPermissions: []string{"read:orders"}},
			},
		})
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		Eventually(func(g Gomega) {
			body := getFromPocketID("/api/api-access/" + clientID + "/apis")
			g.Expect(body).NotTo(ContainSubstring(billingPermID),
				"the dropped API's grant should be gone")
			g.Expect(body).To(ContainSubstring(ordersPermID),
				"the surviving entry must not be collateral damage")
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		By("verifying status dropped only the revoked API")
		Eventually(func(g Gomega) {
			out := getField("pocketidoidcclient", clientName, userNS, ".status.managedAPIs[*]")
			g.Expect(out).To(Equal(ordersID))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	AfterAll(func() {
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
		}, time.Minute, 2*time.Second).Should(Succeed())

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

	AfterAll(func() {
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
		deleteFromPocketID("/api/apis/" + originalAPIID)

		By("waiting for the operator to detect deletion and recreate with a new ID")
		Eventually(func(g Gomega) {
			newID := getField("pocketidapi", apiName, userNS, ".status.apiID")
			g.Expect(newID).NotTo(BeEmpty())
			g.Expect(newID).NotTo(Equal(originalAPIID), "API should have a new ID after recreation")
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the API is Ready and its permission is restored")
		waitForReady("pocketidapi", apiName, userNS)
		Expect(permIDFromStatus(apiName, "read:ext")).NotTo(BeEmpty())
	})

	AfterAll(func() {
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

		body := getFromPocketID("/api/apis/" + existingID)
		Expect(body).To(ContainSubstring("Adopted API"))
		Expect(body).To(ContainSubstring("read:adopt"))
	})

	AfterAll(func() {
		_ = deleteObjectAndWait("pocketidapi", apiName, userNS, time.Minute)
	})
})
