//go:build e2e
// +build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Back-Channel Logout", Ordered, func() {
	// Verifies that spec.backchannelLogoutUrl is persisted and returned by Pocket-ID, which is
	// what keeps it from diffing on every reconcile, and that removing it clears the server
	// value: the operator omits an empty URL and relies on Pocket-ID treating that as unset.

	const (
		clientName = "test-backchannel-logout"
		logoutURL  = "https://backchannel.example.com/logout"
	)

	var clientID string

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})

	It("should propagate spec.backchannelLogoutUrl to Pocket-ID", func() {
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:                 clientName,
			CallbackURLs:         []string{"https://backchannel.example.com/callback"},
			BackchannelLogoutURL: logoutURL,
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		Expect(getOIDCClientFromPocketID(clientID)).To(ContainSubstring(`"backchannelLogoutURL":"` + logoutURL + `"`))
	})

	It("should clear the URL in Pocket-ID when removed from the spec", func() {
		Expect(patchObject("pocketidoidcclient", clientName, userNS,
			`{"spec":{"backchannelLogoutUrl":null}}`)).To(Succeed())

		Eventually(func() string {
			return getOIDCClientFromPocketID(clientID)
		}).Should(ContainSubstring(`"backchannelLogoutURL":""`))
	})
})

var _ = Describe("OIDC Client Group Restriction Back-Channel Logout", Ordered, func() {
	// Pocket-ID sends a logout token to every authorized user outside a client's allowed
	// groups the moment the client's restriction or groups change. Verifies against a live
	// Pocket-ID that restricting a client logs out only the users the new groups exclude,
	// and lifting the restriction logs out no one: what the operator relies on is that
	// groups set on an unrestricted client persist, and are what restriction is checked
	// against when it is turned on.

	const (
		clientName   = "test-bcl-restriction"
		groupName    = "test-bcl-restriction-group"
		memberName   = "test-bcl-member"
		outsiderName = "test-bcl-outsider"
		receiverName = "bcl-receiver"
		callbackURL  = "https://bcl-restriction.example.com/callback"
	)

	var clientID, memberID, outsiderID string

	BeforeAll(func() {
		deployLogoutReceiver(receiverName)

		createUserAndWaitReady(UserOptions{Name: memberName})
		createUserAndWaitReady(UserOptions{Name: outsiderName})
		memberID = waitForStatusFieldNotEmpty("pocketiduser", memberName, userNS, ".status.userID")
		outsiderID = waitForStatusFieldNotEmpty("pocketiduser", outsiderName, userNS, ".status.userID")

		createUserGroupAndWaitReady(UserGroupOptions{
			Name:     groupName,
			UserRefs: []ResourceRef{{Name: memberName}},
		})

		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:                 clientName,
			CallbackURLs:         []string{callbackURL},
			BackchannelLogoutURL: fmt.Sprintf("http://%s.%s.svc:8080/logout", receiverName, userNS),
			SkipConsent:          true,
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		for _, user := range []string{memberName, outsiderName} {
			token := waitForStatusFieldNotEmpty("pocketiduser", user, userNS, ".status.oneTimeLoginToken")
			authorizeOIDCClient(pocketIDSessionForOneTimeToken(token), clientID, callbackURL)
		}
	})

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		deleteObject("pocketidusergroup", groupName, userNS)
		deleteObject("pocketiduser", memberName, userNS)
		deleteObject("pocketiduser", outsiderName, userNS)
		deleteObject("pod", receiverName, userNS)
		deleteObject("service", receiverName, userNS)
	})

	It("should log out only users outside the group when restricting the client", func() {
		Expect(patchObject("pocketidoidcclient", clientName, userNS,
			fmt.Sprintf(`{"spec":{"allowedUserGroups":[{"name":%q}]}}`, groupName))).To(Succeed())
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		// The outsider's logout proves deliveries reach the receiver; the member's would be
		// dispatched by the same notification, so it would have landed alongside.
		Eventually(func() []string { return loggedOutUserIDs(receiverName) }).
			Should(ContainElement(outsiderID))
		Consistently(func() []string { return loggedOutUserIDs(receiverName) }, 5*time.Second).
			Should(Equal([]string{outsiderID}), "the group member %s must stay logged in", memberID)
	})

	It("should log out no one when lifting the restriction", func() {
		Expect(patchObject("pocketidoidcclient", clientName, userNS,
			`{"spec":{"allowedUserGroups":null}}`)).To(Succeed())
		waitForReconciled("pocketidoidcclient", clientName, userNS)

		Expect(getOIDCClientFromPocketID(clientID)).To(ContainSubstring(`"isGroupRestricted":false`))
		Consistently(func() []string { return loggedOutUserIDs(receiverName) }, 10*time.Second).
			Should(Equal([]string{outsiderID}), "lifting the restriction must not log anyone out")
	})
})

// deployLogoutReceiver runs a pod and Service that accept back-channel logout POSTs on port
// 8080 and print each logout token to stdout, for loggedOutUserIDs to read back.
func deployLogoutReceiver(name string) {
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
  - name: receiver
    # renovate: datasource=docker depName=docker.io/library/python versioning=docker
    image: docker.io/library/python:3.14.8-alpine
    command: ["python", "-u", "-c"]
    args:
    - |
      import http.server, urllib.parse
      class Handler(http.server.BaseHTTPRequestHandler):
          def do_POST(self):
              body = self.rfile.read(int(self.headers["Content-Length"])).decode()
              print(urllib.parse.parse_qs(body)["logout_token"][0])
              self.send_response(200)
              self.end_headers()
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

// loggedOutUserIDs returns the subject of each logout token the receiver has been sent.
func loggedOutUserIDs(receiver string) []string {
	GinkgoHelper()

	var subjects []string
	for _, token := range strings.Fields(podLogs(receiver, userNS)) {
		parts := strings.Split(token, ".")
		Expect(parts).To(HaveLen(3), "the receiver should only log JWTs: %q", token)
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		Expect(err).NotTo(HaveOccurred())
		var claims struct {
			Sub string `json:"sub"`
		}
		Expect(json.Unmarshal(payload, &claims)).To(Succeed())
		subjects = append(subjects, claims.Sub)
	}
	return subjects
}

// authorizeOIDCClient records the session's user as having authorized the client, as
// signing in to it would. The client must skip consent, so /authorize grants immediately
// and redirects back with a code rather than to an interaction page.
func authorizeOIDCClient(session *http.Cookie, clientID, callbackURL string) {
	GinkgoHelper()

	ctx, cancel := testCtx()
	defer cancel()

	query := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {callbackURL},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"e2e-state-value"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pocketIDBaseURL()+"/authorize?"+query.Encode(), nil)
	Expect(err).NotTo(HaveOccurred())
	req.AddCookie(session)

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirect.Do(req)
	Expect(err).NotTo(HaveOccurred(), "calling /authorize")
	defer func() { _ = resp.Body.Close() }()

	location := resp.Header.Get("Location")
	Expect(resp.StatusCode).To(Equal(http.StatusFound), "/authorize returned %d", resp.StatusCode)
	Expect(location).To(HavePrefix(callbackURL), "/authorize should grant straight away")
	Expect(location).To(ContainSubstring("code="), "/authorize should grant straight away")
}
