//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
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
			body := getFromPocketID("verify-orders-api", userNS, "/api/apis/"+apiID)
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
				out := kubectlGet("pocketidapi", apiName, "-n", userNS,
					"-o", "jsonpath={.status.permissions[?(@.key=='delete:orders')].id}")
				g.Expect(out).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("confirming Pocket-ID's database contains the new permission")
			body := getFromPocketID("verify-add-perm", userNS, "/api/apis/"+apiID)
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
				out := kubectlGet("pocketidapi", apiName, "-n", userNS,
					"-o", "jsonpath={.status.permissions[?(@.key=='delete:orders')].id}")
				g.Expect(out).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("confirming Pocket-ID's database no longer contains the permission")
			body := getFromPocketID("verify-remove-perm", userNS, "/api/apis/"+apiID)
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
				out := kubectlGet("pocketidapi", apiName, "-n", userNS,
					"-o", "jsonpath={.status.permissions[?(@.key=='write:orders')].name}")
				g.Expect(out).To(Equal("Write and modify orders"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the permission ID is unchanged (updated in place, not recreated)")
			Expect(permIDFromStatus(apiName, "write:orders")).To(Equal(originalID))

			By("confirming Pocket-ID's database reflects the new display fields")
			body := getFromPocketID("verify-update-perm", userNS, "/api/apis/"+apiID)
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
			Expect(kubectlGet("pocketidapi", apiName, "-n", userNS,
				"-o", "jsonpath={.status.apiID}")).To(Equal(apiID))
			Expect(kubectlGet("pocketidapi", apiName, "-n", userNS,
				"-o", "jsonpath={.status.resource}")).To(Equal(resource))

			By("confirming Pocket-ID's database reflects the rename")
			body := getFromPocketID("verify-rename", userNS, "/api/apis/"+apiID)
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
		body := getFromPocketID("verify-defaulted", userNS, "/api/apis/"+apiID)
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
			out := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.managedAPIPermissionIDs[*]}")
			g.Expect(out).To(ContainSubstring(readID))
			g.Expect(out).To(ContainSubstring(syncID))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("should reflect the delegated/client split in Pocket-ID's database", func() {
		body := getFromPocketID("verify-access", userNS, "/api/api-access/"+clientID)
		// read:data was granted for the user-delegated flow, sync:data for client-credentials.
		Expect(body).To(ContainSubstring(fmt.Sprintf(`"userDelegatedPermissionIds":["%s"]`, readID)))
		Expect(body).To(ContainSubstring(fmt.Sprintf(`"clientPermissionIds":["%s"]`, syncID)))
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
		body := getFromPocketID("verify-access-update", userNS, "/api/api-access/"+clientID)
		// clientPermissionIds empty + both IDs present proves both are now user-delegated.
		Expect(body).To(ContainSubstring(`"clientPermissionIds":[]`))
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
			out := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.managedAPIPermissionIDs[*]}")
			g.Expect(out).To(BeEmpty())
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		By("confirming Pocket-ID's database has no access for the client")
		body := getFromPocketID("verify-access-clear", userNS, "/api/api-access/"+clientID)
		Expect(body).NotTo(ContainSubstring(readID))
		Expect(body).NotTo(ContainSubstring(syncID))
	})

	AfterAll(func() {
		kubectlDelete("pocketidoidcclient", clientName, userNS)
		_ = kubectlDeleteWait("pocketidapi", apiName, userNS, time.Minute)
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
		cmd := exec.Command("kubectl", "delete", "pocketidapi", apiName, "-n", userNS, "--wait=false")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("verifying deletion is blocked by the reference finalizer")
		Eventually(func(g Gomega) {
			ts := kubectlGet("pocketidapi", apiName, "-n", userNS,
				"-o", "jsonpath={.metadata.deletionTimestamp}")
			fin := kubectlGet("pocketidapi", apiName, "-n", userNS,
				"-o", "jsonpath={.metadata.finalizers}")
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
		kubectlDelete("pocketidoidcclient", clientName, userNS)
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
		deleteFromPocketID("delete-api-ext", userNS, "/api/apis/"+originalAPIID)

		By("waiting for the operator to detect deletion and recreate with a new ID")
		Eventually(func(g Gomega) {
			newID := kubectlGet("pocketidapi", apiName, "-n", userNS,
				"-o", "jsonpath={.status.apiID}")
			g.Expect(newID).NotTo(BeEmpty())
			g.Expect(newID).NotTo(Equal(originalAPIID), "API should have a new ID after recreation")
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the API is Ready and its permission is restored")
		waitForReady("pocketidapi", apiName, userNS)
		Expect(permIDFromStatus(apiName, "read:ext")).NotTo(BeEmpty())
	})

	AfterAll(func() {
		_ = kubectlDeleteWait("pocketidapi", apiName, userNS, time.Minute)
	})
})

var _ = Describe("PocketIDAPI Adoption", Ordered, func() {
	const (
		apiName  = "adopt-api"
		resource = "https://adopt.e2e.example.com"
	)

	It("should adopt a pre-existing API matched by resource and take ownership", func() {
		By("creating an API directly in Pocket-ID (simulating the UI)")
		existingID := createAPIInPocketID("precreate-adopt-api", userNS, "Pre-created API", resource)
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

		body := getFromPocketID("verify-adopt", userNS, "/api/apis/"+existingID)
		Expect(body).To(ContainSubstring("Adopted API"))
		Expect(body).To(ContainSubstring("read:adopt"))
	})

	AfterAll(func() {
		_ = kubectlDeleteWait("pocketidapi", apiName, userNS, time.Minute)
	})
})
