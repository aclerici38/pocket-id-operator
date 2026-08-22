//go:build e2e
// +build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

var _ = Describe("Resource Adoption", Ordered, func() {
	// These tests verify that when a resource already exists in Pocket-ID,
	// the operator correctly adopts it instead of failing with a conflict error.
	// This tests the "create-first, adopt-on-conflict" pattern.

	Context("User Adoption", func() {
		const userName = "test-adopt-user"
		const pocketIDUsername = "adopt-test-user"

		It("should adopt an existing user from Pocket-ID", func() {
			By("creating a user directly in Pocket-ID via API")
			userID := createUserInPocketID(pocketIDUsername, "Adopt", "Test", "adopt-test@example.local")

			By("creating a PocketIDUser CR with the same username")
			createUser(UserOptions{
				Name:      userName,
				Username:  pocketIDUsername,
				FirstName: "Adopt",
				LastName:  "Test",
				Email:     "adopt-test@example.local",
			})

			By("waiting for the user to be ready")
			waitForReady("pocketiduser", userName, userNS)

			By("verifying the operator adopted the existing user (same user ID)")
			adoptedUserID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")
			Expect(adoptedUserID).To(Equal(userID), "operator should adopt the existing user, not create a new one")
		})

		AfterAll(func() {
			deleteObject("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)
		})
	})

	Context("UserGroup Adoption", func() {
		const groupName = "test-adopt-group"
		const pocketIDGroupName = "adopt-test-group"

		It("should adopt an existing user group from Pocket-ID", func() {
			By("creating a user group directly in Pocket-ID via API")
			groupID := createUserGroupInPocketID(pocketIDGroupName, "Adopt Test Group")

			By("creating a PocketIDUserGroup CR with the same name")
			createUserGroup(UserGroupOptions{
				Name:         groupName,
				GroupName:    pocketIDGroupName,
				FriendlyName: "Adopt Test Group",
			})

			By("waiting for the group to be ready")
			waitForReady("pocketidusergroup", groupName, userNS)

			By("verifying the operator adopted the existing group (same group ID)")
			adoptedGroupID := waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupID")
			Expect(adoptedGroupID).To(Equal(groupID), "operator should adopt the existing group, not create a new one")
		})

		AfterAll(func() {
			deleteObject("pocketidusergroup", groupName, userNS)
			waitForResourceDeleted("pocketidusergroup", groupName, userNS)
		})
	})

	Context("OIDCClient Adoption", func() {
		const clientName = "test-adopt-oidc"
		const pocketIDClientID = "adopt-test-oidc-client"

		It("should adopt an existing OIDC client from Pocket-ID", func() {
			By("creating an OIDC client directly in Pocket-ID via API")
			createOIDCClientInPocketID(pocketIDClientID, "Adopt Test OIDC", []string{"https://adopt-test.example.com/callback"})

			By("creating a PocketIDOIDCClient CR with the same client ID")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				ClientID:     pocketIDClientID,
				CallbackURLs: []string{"https://adopt-test.example.com/callback"},
			})

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the operator adopted the existing client (same client ID)")
			adoptedClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Expect(adoptedClientID).To(Equal(pocketIDClientID), "operator should adopt the existing client, not create a new one")
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("OIDCClient Adoption by name", func() {
		// This tests the case where the OIDC client in Pocket-ID has a different ID
		// but the same name as the CR. The operator should find it by name search.
		const clientName = "test-adopt-oidc-by-name"

		It("should adopt an existing OIDC client by matching name when no clientID is specified", func() {
			By("creating an OIDC client directly in Pocket-ID with a random ID but name matching the CR name")
			// The client ID in Pocket-ID will be different from the CR name,
			// but the name field will match. The operator should find it by name.
			externalClientID := createOIDCClientInPocketIDWithName(clientName, []string{"https://adopt-byname.example.com/callback"})

			By("creating a PocketIDOIDCClient CR without explicit clientID")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://adopt-byname.example.com/callback"},
				// Note: ClientID is intentionally not set - operator will search by name
			})

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the operator adopted the existing client (same client ID)")
			adoptedClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Expect(adoptedClientID).To(Equal(externalClientID), "operator should adopt the existing client, not create a new one")
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// createUserInPocketID creates a user directly via the Pocket-ID API, bypassing the
// operator, and returns the new user's ID. Pocket-ID requires a displayName, so it is
// derived from the name parts the way a UI form would.
func createUserInPocketID(username, firstName, lastName, email string) string {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	user, err := pid.CreateUser(ctx, pocketid.UserInput{
		Username:    username,
		FirstName:   firstName,
		LastName:    lastName,
		Email:       email,
		DisplayName: firstName + " " + lastName,
	})
	Expect(err).NotTo(HaveOccurred(), "creating user %q", username)
	Expect(user.ID).NotTo(BeEmpty())
	return user.ID
}

// createUserGroupInPocketID creates a user group directly via the Pocket-ID API,
// bypassing the operator, and returns its ID.
func createUserGroupInPocketID(name, friendlyName string) string {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	group, err := pid.CreateUserGroup(ctx, name, friendlyName)
	Expect(err).NotTo(HaveOccurred(), "creating group %q", name)
	Expect(group.ID).NotTo(BeEmpty())
	return group.ID
}

// createOIDCClientInPocketID creates an OIDC client directly in Pocket-ID under a
// caller-chosen client ID, so a later CR can be shown to adopt it rather than create a
// second one.
func createOIDCClientInPocketID(clientID, name string, callbackURLs []string) {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	_, err := pid.CreateOIDCClient(ctx, pocketid.OIDCClientInput{
		ID:           &clientID,
		Name:         name,
		CallbackURLs: callbackURLs,
	})
	Expect(err).NotTo(HaveOccurred(), "creating OIDC client %q", clientID)
}

// createOIDCClientInPocketIDWithName creates an OIDC client without naming its ID, so
// Pocket-ID autogenerates one, and returns that ID. Used to test adoption by name.
func createOIDCClientInPocketIDWithName(name string, callbackURLs []string) string {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	client, err := pid.CreateOIDCClient(ctx, pocketid.OIDCClientInput{
		Name:         name,
		CallbackURLs: callbackURLs,
	})
	Expect(err).NotTo(HaveOccurred(), "creating OIDC client %q", name)
	Expect(client.ID).NotTo(BeEmpty())
	return client.ID
}
