//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Email Verification Preservation", Ordered, func() {
	// This test verifies that when a user verifies their email via the Pocket-ID UI,
	// subsequent operator reconciles do not reset emailVerified back to false.
	// The fix is to read emailVerified from GetUser into status, then send it back
	// in UpdateUser on every reconcile.

	Context("Email verified status is preserved across reconciles", func() {
		const userName = "test-email-verified-user"
		const pocketIDUsername = "email-verified-test-user"
		const podName = "verify-email-pod"
		const checkPodName = "check-email-verified-pod"

		It("should reflect emailVerified=true in status after adoption and preserve it on reconcile", func() {
			By("creating a user in Pocket-ID with emailVerified=true via the admin API")
			userID := createUserWithEmailVerified("create-email-verified-pod", userNS, pocketIDUsername, "Email", "Verified", "email-verified@example.local")

			By("creating a PocketIDUser CR that adopts the existing user")
			createUser(UserOptions{
				Name:      userName,
				Username:  pocketIDUsername,
				FirstName: "Email",
				LastName:  "Verified",
				Email:     "email-verified@example.local",
			})
			waitForReady("pocketiduser", userName, userNS)

			By("verifying the operator adopted the user")
			adoptedUserID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")
			Expect(adoptedUserID).To(Equal(userID))

			By("verifying status.emailVerified is true after sync")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.emailVerified}")
				g.Expect(output).To(Equal("true"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("triggering another reconcile by patching the spec")
			Expect(kubectlAnnotate("pocketiduser", userName, userNS, "test/reconcile-trigger=1")).To(Succeed())

			By("waiting for reconcile to complete")
			waitForReady("pocketiduser", userName, userNS)

			By("verifying emailVerified is still true in Pocket-ID after reconcile")
			tokenBase64 := getStaticAPIKeyToken()
			Expect(tokenBase64).NotTo(BeEmpty())
			script := fmt.Sprintf(`TOKEN=$(echo '%s' | base64 -d)
RESPONSE=$(curl -sf -H "X-API-KEY: $TOKEN" %s/api/users/%s)
echo "$RESPONSE" | grep -q '"emailVerified":true'`,
				tokenBase64, formatInstanceURL(), userID)
			applyYAML(createCurlPodYAML(checkPodName, userNS, script))
			waitForPodSucceeded(checkPodName, userNS)
		})

		AfterAll(func() {
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)
		})
	})

	Context("New users created by operator start unverified", func() {
		const userName = "test-new-user-unverified"

		BeforeAll(func() {
			createUserAndWaitReady(UserOptions{
				Name:  userName,
				Email: "new-unverified@example.local",
			})
		})

		It("should not show emailVerified in status for a freshly created user", func() {
			output := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.emailVerified}")
			Expect(output).To(BeEmpty())
		})
	})
})

// createUserWithEmailVerified creates a user directly in Pocket-ID via the admin API
// with emailVerified=true and returns the user ID.
func createUserWithEmailVerified(podName, namespace, username, firstName, lastName, email string) string {
	apiKeyBase64 := getStaticAPIKeyToken()
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	displayName := firstName + " " + lastName
	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
RESPONSE=$(curl -s -X POST -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '{"username": "%s", "firstName": "%s", "lastName": "%s", "email": "%s", "displayName": "%s", "emailVerified": true}' \
  -w '\n%%{http_code}' \
  %s/api/users)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
  echo "Failed to create user with HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi
echo "$BODY" | sed 's/.*"id":"\([^"]*\)".*/\1/'`,
		apiKeyBase64, username, firstName, lastName, email, displayName, formatInstanceURL())

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)

	userID := getPodLogs(podName, namespace)
	Expect(userID).NotTo(BeEmpty(), "should get user ID from API response")
	return userID
}
