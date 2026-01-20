//go:build e2e
// +build e2e

package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
			userID := createUserInPocketID("create-adopt-user-pod", userNS, pocketIDUsername, "Adopt", "Test", "adopt-test@example.local")

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
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)
		})
	})

	Context("UserGroup Adoption", func() {
		const groupName = "test-adopt-group"
		const pocketIDGroupName = "adopt-test-group"

		It("should adopt an existing user group from Pocket-ID", func() {
			By("creating a user group directly in Pocket-ID via API")
			groupID := createUserGroupInPocketID("create-adopt-group-pod", userNS, pocketIDGroupName, "Adopt Test Group")

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
			kubectlDelete("pocketidusergroup", groupName, userNS)
			waitForResourceDeleted("pocketidusergroup", groupName, userNS)
		})
	})

	Context("OIDCClient Adoption", func() {
		const clientName = "test-adopt-oidc"
		const pocketIDClientID = "adopt-test-oidc-client"

		It("should adopt an existing OIDC client from Pocket-ID", func() {
			By("creating an OIDC client directly in Pocket-ID via API")
			createOIDCClientInPocketID("create-adopt-oidc-pod", userNS, pocketIDClientID, "Adopt Test OIDC", []string{"https://adopt-test.example.com/callback"})

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
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("OIDCClient Adoption with default clientID", func() {
		// This tests the case where spec.clientID is not set, so the operator
		// uses the resource name as the client ID
		const clientName = "test-adopt-oidc-default-id"

		It("should adopt an existing OIDC client when using resource name as client ID", func() {
			By("creating an OIDC client directly in Pocket-ID with ID matching the CR name")
			createOIDCClientInPocketID("create-adopt-oidc-default-pod", userNS, clientName, "Adopt Test Default ID", []string{"https://adopt-default.example.com/callback"})

			By("creating a PocketIDOIDCClient CR without explicit clientID (will use resource name)")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://adopt-default.example.com/callback"},
				// Note: ClientID is intentionally not set - should default to Name
			})

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the operator adopted the existing client")
			adoptedClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Expect(adoptedClientID).To(Equal(clientName), "operator should adopt the existing client using resource name as client ID")
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// createUserInPocketID creates a user directly in Pocket-ID via the API and returns the user ID
func createUserInPocketID(podName, namespace, username, firstName, lastName, email string) string {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	// Create user and capture the ID from the response
	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
RESPONSE=$(curl -sf -X POST -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '{"username": "%s", "firstName": "%s", "lastName": "%s", "email": "%s"}' \
  %s/api/users)
if [ $? -ne 0 ]; then
  echo "Failed to create user" >&2
  exit 1
fi
# Extract and print the user ID
echo "$RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4`,
		apiKeyBase64, username, firstName, lastName, email, formatInstanceURL())

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)

	// Get the user ID from pod logs
	userID := getPodLogs(podName, namespace)
	Expect(userID).NotTo(BeEmpty(), "should get user ID from API response")

	return userID
}

// createUserGroupInPocketID creates a user group directly in Pocket-ID via the API and returns the group ID
func createUserGroupInPocketID(podName, namespace, name, friendlyName string) string {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
RESPONSE=$(curl -sf -X POST -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "%s", "friendlyName": "%s"}' \
  %s/api/user-groups)
if [ $? -ne 0 ]; then
  echo "Failed to create user group" >&2
  exit 1
fi
# Extract and print the group ID
echo "$RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4`,
		apiKeyBase64, name, friendlyName, formatInstanceURL())

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)

	// Get the group ID from pod logs
	groupID := getPodLogs(podName, namespace)
	Expect(groupID).NotTo(BeEmpty(), "should get group ID from API response")

	return groupID
}

// createOIDCClientInPocketID creates an OIDC client directly in Pocket-ID via the API
func createOIDCClientInPocketID(podName, namespace, clientID, name string, callbackURLs []string) {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	// Build callback URLs JSON array
	callbackURLsJSON := "["
	for i, url := range callbackURLs {
		if i > 0 {
			callbackURLsJSON += ","
		}
		callbackURLsJSON += fmt.Sprintf(`"%s"`, url)
	}
	callbackURLsJSON += "]"

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
HTTP_CODE=$(curl -sf -o /dev/null -w '%%{http_code}' -X POST -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '{"id": "%s", "name": "%s", "callbackURLs": %s}' \
  %s/api/oidc/clients)
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
  echo "Failed to create OIDC client with HTTP $HTTP_CODE" >&2
  exit 1
fi
echo "OIDC client created successfully"`,
		apiKeyBase64, clientID, name, callbackURLsJSON, formatInstanceURL())

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
}
