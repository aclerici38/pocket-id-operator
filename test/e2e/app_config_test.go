//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// getAppConfigValue queries the Pocket-ID API for a single app config key.
func getAppConfigValue(podName, namespace, key string) string {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
BODY=$(curl -s -H "X-API-KEY: $API_KEY" %s/api/application-configuration)
echo "$BODY" | sed 's/},{/}\n{/g' | grep '"key":"%s"' | sed 's/.*"value":"//;s/".*//'`,
		apiKeyBase64, formatInstanceURL(), key)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	return getPodLogs(podName, namespace)
}

// setAppConfigValue updates a single app config key directly via the Pocket-ID API,
// simulating a user changing it through the UI.
func setAppConfigValue(podName, namespace, key, value string) {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
HTTP_CODE=$(curl -s -o /dev/null -w '%%{http_code}' -X PUT \
  -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '{"%s":"%s"}' \
  %s/api/application-configuration)
if [ "$HTTP_CODE" != "200" ]; then
  echo "Failed: HTTP $HTTP_CODE" >&2
  exit 1
fi
echo "ok"`,
		apiKeyBase64, key, value, formatInstanceURL())

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
}

var _ = Describe("App Configuration", func() {
	// All tests use the shared e2e instance.

	Context("CRD config is applied to the API", func() {
		It("should set appName and accentColor via UI config", func() {
			By("patching the shared instance with UI config")
			Expect(kubectlPatch("pocketidinstance", instanceName, instanceNS,
				`{"spec":{"ui":{"appName":"CRD Applied Test","accentColor":"#aabb00"}}}`)).To(Succeed())

			By("verifying appName in the API")
			Eventually(func(g Gomega) {
				podName := "cfg-applied-name"
				kubectlDelete("pod", podName, instanceNS)
				g.Expect(getAppConfigValue(podName, instanceNS, "appName")).To(Equal("CRD Applied Test"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying accentColor in the API")
			Eventually(func(g Gomega) {
				podName := "cfg-applied-color"
				kubectlDelete("pod", podName, instanceNS)
				g.Expect(getAppConfigValue(podName, instanceNS, "accentColor")).To(Equal("#aabb00"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	Context("CRD update is picked up", func() {
		It("should reflect a patched appName in the API", func() {
			By("setting an initial appName")
			Expect(kubectlPatch("pocketidinstance", instanceName, instanceNS,
				`{"spec":{"ui":{"appName":"Before Update"}}}`)).To(Succeed())

			Eventually(func(g Gomega) {
				podName := "cfg-update-before"
				kubectlDelete("pod", podName, instanceNS)
				g.Expect(getAppConfigValue(podName, instanceNS, "appName")).To(Equal("Before Update"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("patching to a new appName")
			Expect(kubectlPatch("pocketidinstance", instanceName, instanceNS,
				`{"spec":{"ui":{"appName":"After Update"}}}`)).To(Succeed())

			By("verifying the API reflects the new value")
			Eventually(func(g Gomega) {
				podName := "cfg-update-after"
				kubectlDelete("pod", podName, instanceNS)
				g.Expect(getAppConfigValue(podName, instanceNS, "appName")).To(Equal("After Update"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	Context("Unmanaged fields are preserved", func() {
		It("should not reset sessionDuration when appName is changed", func() {
			By("reading the current sessionDuration")
			podName := "cfg-preserve-before"
			kubectlDelete("pod", podName, instanceNS)
			originalSession := getAppConfigValue(podName, instanceNS, "sessionDuration")
			Expect(originalSession).NotTo(BeEmpty())

			By("patching only appName")
			Expect(kubectlPatch("pocketidinstance", instanceName, instanceNS,
				`{"spec":{"ui":{"appName":"Preserve Check"}}}`)).To(Succeed())

			By("waiting for the appName change to propagate")
			Eventually(func(g Gomega) {
				podName := "cfg-preserve-verify-name"
				kubectlDelete("pod", podName, instanceNS)
				g.Expect(getAppConfigValue(podName, instanceNS, "appName")).To(Equal("Preserve Check"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying sessionDuration was not changed")
			podName = "cfg-preserve-after"
			kubectlDelete("pod", podName, instanceNS)
			Expect(getAppConfigValue(podName, instanceNS, "sessionDuration")).To(Equal(originalSession))
		})
	})

	Context("API-side change is overwritten by CRD", func() {
		It("should revert an appName changed directly via the API back to the CRD value", func() {
			By("setting appName via CRD")
			Expect(kubectlPatch("pocketidinstance", instanceName, instanceNS,
				`{"spec":{"ui":{"appName":"CRD Wins"}}}`)).To(Succeed())

			Eventually(func(g Gomega) {
				podName := "cfg-overwrite-set"
				kubectlDelete("pod", podName, instanceNS)
				g.Expect(getAppConfigValue(podName, instanceNS, "appName")).To(Equal("CRD Wins"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("changing appName directly via the Pocket-ID API (simulating UI edit)")
			podName := "cfg-overwrite-api"
			kubectlDelete("pod", podName, instanceNS)
			setAppConfigValue(podName, instanceNS, "appName", "UI Override")

			By("triggering a reconcile by annotating the instance")
			Expect(kubectlAnnotate("pocketidinstance", instanceName, instanceNS,
				fmt.Sprintf("pocketid.internal/reconcile-trigger=%d", time.Now().Unix()))).To(Succeed())

			By("verifying the controller overwrites the API-side change back to the CRD value")
			Eventually(func(g Gomega) {
				podName := "cfg-overwrite-check"
				kubectlDelete("pod", podName, instanceNS)
				g.Expect(getAppConfigValue(podName, instanceNS, "appName")).To(Equal("CRD Wins"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})
