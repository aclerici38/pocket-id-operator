//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
)

var _ = Describe("HTTPRoute", Serial, Ordered, func() {
	const (
		routeName       = "e2e-instance-route"
		initialHostname = "route.e2e.example.com"
		updatedHostname = "route-updated.e2e.example.com"
	)

	setSharedInstanceRoute := func(enabled bool, hostnames []string) {
		quotedHostnames := make([]string, 0, len(hostnames))
		for _, hostname := range hostnames {
			quotedHostnames = append(quotedHostnames, fmt.Sprintf("%q", hostname))
		}

		patch := fmt.Sprintf(
			`{"spec":{"route":{"enabled":%t,"name":"%s","parentRefs":[{"group":"gateway.networking.k8s.io","kind":"Gateway","name":"gateway"}],"hostnames":[%s]}}}`,
			enabled,
			routeName,
			strings.Join(quotedHostnames, ","),
		)

		err := kubectlPatch("pocketidinstance", instanceName, instanceNS, patch)
		Expect(err).NotTo(HaveOccurred())
	}

	operatorControllerPodName := func() string {
		return kubectlGet("pod", "-n", namespace, "-l", "control-plane=controller-manager", "-o", "jsonpath={.items[0].metadata.name}")
	}

	installGatewayHTTPRouteCRD := func() {
		gatewayCRDPath, err := gatewayAPIHTTPRouteCRDPath()
		Expect(err).NotTo(HaveOccurred())

		cmd := exec.Command("kubectl", "apply", "-f", gatewayCRDPath)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	}

	uninstallGatewayHTTPRouteCRD := func() {
		gatewayCRDPath, err := gatewayAPIHTTPRouteCRDPath()
		Expect(err).NotTo(HaveOccurred())

		cmd := exec.Command("kubectl", "delete", "--ignore-not-found", "-f", gatewayCRDPath)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	}

	BeforeAll(func() {
		uninstallGatewayHTTPRouteCRD()
		waitForReady("pocketidinstance", instanceName, instanceNS)
		setSharedInstanceRoute(false, nil)
		waitForResourceDeleted("httproute", routeName, instanceNS)
	})

	AfterAll(func() {
		setSharedInstanceRoute(false, nil)
		waitForResourceDeleted("httproute", routeName, instanceNS)
		uninstallGatewayHTTPRouteCRD()
	})

	It("should log an error when route is enabled without Gateway API CRDs", func() {
		setSharedInstanceRoute(true, []string{initialHostname})

		Eventually(func(g Gomega) {
			podName := operatorControllerPodName()
			g.Expect(podName).NotTo(BeEmpty())

			logs := kubectlLogs(podName, namespace)
			g.Expect(logs).To(ContainSubstring("httproute is enabled but Gateway API CRDs are not installed"))

			route := kubectlGet("httproute", routeName, "-n", instanceNS, "-o", "name")
			g.Expect(route).To(BeEmpty())
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("should create, update, and delete HTTPRoute after installing the CRD", func() {
		installGatewayHTTPRouteCRD()
		setSharedInstanceRoute(true, []string{updatedHostname})

		Eventually(func(g Gomega) {
			name := kubectlGet("httproute", routeName, "-n", instanceNS, "-o", "jsonpath={.metadata.name}")
			g.Expect(name).To(Equal(routeName))

			backendName := kubectlGet("httproute", routeName, "-n", instanceNS, "-o", "jsonpath={.spec.rules[0].backendRefs[0].name}")
			g.Expect(backendName).To(Equal(instanceName))

			backendPort := kubectlGet("httproute", routeName, "-n", instanceNS, "-o", "jsonpath={.spec.rules[0].backendRefs[0].port}")
			g.Expect(backendPort).To(Equal("1411"))

			hostname := kubectlGet("httproute", routeName, "-n", instanceNS, "-o", "jsonpath={.spec.hostnames[0]}")
			g.Expect(hostname).To(Equal(updatedHostname))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		setSharedInstanceRoute(true, []string{initialHostname})
		Eventually(func(g Gomega) {
			hostname := kubectlGet("httproute", routeName, "-n", instanceNS, "-o", "jsonpath={.spec.hostnames[0]}")
			g.Expect(hostname).To(Equal(initialHostname))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		setSharedInstanceRoute(false, nil)
		waitForResourceDeleted("httproute", routeName, instanceNS)
	})
})
