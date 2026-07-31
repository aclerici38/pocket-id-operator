//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/aclerici38/pocket-id-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// pocketIDUser is the subset of Pocket-ID's user payload the ID tests assert on.
type pocketIDUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	IsAdmin     bool   `json:"isAdmin"`
	Disabled    bool   `json:"disabled"`
}

// getUserFromPocketID reads a user straight out of Pocket-ID by ID. A 404 makes the
// curl pod fail, so a successful decode also proves the ID exists in Pocket-ID.
func getUserFromPocketID(podName, userID string) pocketIDUser {
	body := getFromPocketID(podName, userNS, "/api/users/"+userID)
	Expect(body).NotTo(BeEmpty(), "Pocket-ID should return a user for ID %s", userID)

	var user pocketIDUser
	Expect(json.Unmarshal([]byte(body), &user)).To(Succeed(), "response body: %s", body)
	return user
}

var _ = Describe("PocketIDUser Declarative User ID", Ordered, func() {
	Context("User created with a declared ID", func() {
		const (
			userName    = "test-declarative-userid"
			declaredID  = "3f8a1c72-9b4d-4e61-8a0f-2c5d7e9b1a34"
			userEmail   = "declared-id@example.com"
			firstName   = "Declared"
			lastName    = "Ident"
			displayName = "Declared Ident"
		)

		BeforeAll(func() {
			createUser(UserOptions{
				Name:        userName,
				UserID:      declaredID,
				Email:       userEmail,
				FirstName:   firstName,
				LastName:    lastName,
				DisplayName: displayName,
			})
			waitForReady("pocketiduser", userName, userNS)
		})

		It("should use the declared ID as status.userID", func() {
			waitForStatusField("pocketiduser", userName, userNS, ".status.userID", declaredID)
		})

		It("should return the user's true state from Pocket-ID for the declared ID", func() {
			user := getUserFromPocketID("verify-declared-userid", declaredID)

			Expect(user.ID).To(Equal(declaredID),
				"Pocket-ID should store the user under the declared ID")
			Expect(user.Username).To(Equal(userName))
			Expect(user.FirstName).To(Equal(firstName))
			Expect(user.LastName).To(Equal(lastName))
			Expect(user.Email).To(Equal(userEmail))
			Expect(user.DisplayName).To(Equal(displayName))
			Expect(user.IsAdmin).To(BeFalse())
			Expect(user.Disabled).To(BeFalse())
		})

		It("should reflect a spec change on the same declared ID", func() {
			By("changing the display name and promoting the user to admin")
			admin := true
			applyYAML(buildUserYAML(UserOptions{
				Name:        userName,
				UserID:      declaredID,
				Email:       userEmail,
				FirstName:   firstName,
				LastName:    lastName,
				DisplayName: "Renamed Ident",
				Admin:       &admin,
			}))

			By("waiting for the operator to push the change")
			waitForStatusField("pocketiduser", userName, userNS, ".status.isAdmin", "true")
			waitForStatusField("pocketiduser", userName, userNS, ".status.userID", declaredID)

			By("verifying Pocket-ID returns the updated state under the same ID")
			user := getUserFromPocketID("verify-updated-userid", declaredID)
			Expect(user.ID).To(Equal(declaredID), "the user ID must not change on update")
			Expect(user.DisplayName).To(Equal("Renamed Ident"))
			Expect(user.IsAdmin).To(BeTrue())
		})

		It("should adopt the same Pocket-ID user when the resource is recreated", func() {
			By("deleting the resource (the Pocket-ID user is retained without the delete annotation)")
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)

			By("verifying the user still exists in Pocket-ID")
			Expect(getUserFromPocketID("verify-retained-userid", declaredID).ID).To(Equal(declaredID))

			By("recreating the resource with the same declared ID but a different username")
			createUser(UserOptions{
				Name:      userName,
				UserID:    declaredID,
				Username:  userName + "-readopted",
				Email:     userEmail,
				FirstName: firstName,
				LastName:  lastName,
			})
			waitForReady("pocketiduser", userName, userNS)

			By("verifying the existing user was adopted rather than a second one created")
			waitForStatusField("pocketiduser", userName, userNS, ".status.userID", declaredID)
			Eventually(func(g Gomega) {
				g.Expect(kubectlGetSecretData(userName+"-user-data", userNS, "username")).
					To(Equal(userName + "-readopted"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			user := getUserFromPocketID("verify-readopted-userid", declaredID)
			Expect(user.ID).To(Equal(declaredID))
			Expect(user.Username).To(Equal(userName + "-readopted"))
		})

		It("should reject changing the declared ID", func() {
			yaml := buildUserYAML(UserOptions{
				Name:     userName,
				UserID:   "8c2e5b41-7a3f-4d92-b6e8-1f0a3c5d7e91",
				Username: userName + "-readopted",
				Email:    userEmail,
			})
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "apply should fail due to immutability validation")
			Expect(output).To(ContainSubstring("userID is immutable"))

			By("verifying status.userID is unchanged")
			Expect(kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.userID}")).To(Equal(declaredID))
		})

		It("should reject removing the declared ID", func() {
			yaml := buildUserYAML(UserOptions{
				Name:     userName,
				Username: userName + "-readopted",
				Email:    userEmail,
			})
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "apply should fail due to immutability validation")
			Expect(output).To(ContainSubstring("userID is immutable"))
		})

		AfterAll(func() {
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)
		})
	})

	Context("Autogenerated user ID", func() {
		const userName = "test-autogen-userid"

		It("should let Pocket-ID assign the ID when spec.userID is unset", func() {
			createUser(UserOptions{Name: userName, Email: "autogen-id@example.com"})
			waitForReady("pocketiduser", userName, userNS)

			statusUserID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")
			Expect(statusUserID).NotTo(Equal(userName),
				"status.userID should come from Pocket-ID, not be inferred from the resource name")

			By("verifying Pocket-ID returns the user under the autogenerated ID")
			user := getUserFromPocketID("verify-autogen-userid", statusUserID)
			Expect(user.ID).To(Equal(statusUserID))
			Expect(user.Username).To(Equal(userName))
		})

		It("should allow adding a userID later only if it matches the assigned one", func() {
			assignedID := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.userID}")
			Expect(assignedID).NotTo(BeEmpty())

			yaml := buildUserYAML(UserOptions{
				Name:   userName,
				UserID: assignedID,
				Email:  "autogen-id@example.com",
			})
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(),
				"adding spec.userID after creation should be rejected as immutable")
			Expect(output).To(ContainSubstring("userID is immutable"))
		})

		AfterAll(func() {
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)
		})
	})

	Context("User ID validation", func() {
		It("should reject a userID that is not a lowercase UUID", func() {
			for _, invalid := range []string{
				"not-a-uuid",
				"3F8A1C72-9B4D-4E61-8A0F-2C5D7E9B1A34",
				"3f8a1c729b4d4e618a0f2c5d7e9b1a34",
				"3f8a1c72-9b4d-4e61-8a0f-2c5d7e9b1a34-extra",
			} {
				yaml := buildUserYAML(UserOptions{
					Name:   "test-invalid-userid",
					UserID: invalid,
					Email:  "invalid-id@example.com",
				})
				cmd := exec.Command("kubectl", "apply", "--dry-run=server", "-f", "-")
				cmd.Stdin = strings.NewReader(yaml)
				output, err := utils.Run(cmd)
				Expect(err).To(HaveOccurred(), "userID %q should be rejected", invalid)
				Expect(output).To(ContainSubstring("spec.userID"),
					"rejection should point at spec.userID for %q", invalid)
			}
		})
	})
})
