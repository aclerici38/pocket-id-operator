//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
)

const (
	defaultProjectImage = "pocket-id-operator:e2e"
	namespace           = "pocket-id-operator-system"
)

var projectImage = defaultProjectImage

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	SetDefaultEventuallyTimeout(3 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)
	RunSpecs(t, "Pocket-ID Operator E2E Suite")
}

var _ = BeforeSuite(func() {
	projectImage = resolveProjectImage()

	By("building the operator image")
	if os.Getenv("IMG") == "" {
		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to build operator image")
	} else {
		By("skipping build because IMG is set")
	}

	By("loading the operator image into Kind")
	err := utils.LoadImageToKindClusterWithName(projectImage)
	Expect(err).NotTo(HaveOccurred(), "Failed to load operator image into Kind")

	By("cleaning up any resources from previous runs")
	cleanupAllResources()

	By("installing CRDs")
	cmd := exec.Command("make", "install")
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

	By("deploying the operator with e2e config (faster resync)")
	cmd = exec.Command("make", "deploy-e2e", fmt.Sprintf("IMG=%s", projectImage))
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to deploy operator")

	By("waiting for operator to be ready")
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "deployment", "pocket-id-operator",
			"-n", namespace, "-o", "jsonpath={.status.availableReplicas}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("1"))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())

	By("creating test namespaces")
	createNamespace(instanceNS)
	createNamespace(userNS)

	By("creating encryption key secret")
	applyYAML(createSecretYAML("pocket-id-encryption", instanceNS, map[string]string{
		"key": "e2e-test-encryption-key-32chars!",
	}))

	By("creating the shared e2e instance")
	createInstance(InstanceOptions{})

	By("waiting for the shared instance to be Ready")
	Eventually(func(g Gomega) {
		output := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		g.Expect(output).To(Equal("True"))
	}, 5*time.Minute, 5*time.Second).Should(Succeed())
})

var _ = AfterSuite(func() {
	By("cleaning up test namespace resources")
	removeFinalizers(userNS)
	removeFinalizers(instanceNS)

	By("deleting test namespaces")
	deleteNamespace(userNS)
	deleteNamespace(instanceNS)

	By("cleaning up all resources")
	cleanupAllResources()

	By("undeploying the operator")
	cmd := exec.Command("make", "undeploy", "--ignore-errors")
	_, _ = utils.Run(cmd)

	By("uninstalling CRDs")
	cmd = exec.Command("make", "uninstall", "--ignore-errors")
	_, _ = utils.Run(cmd)
})

func resolveProjectImage() string {
	if img := os.Getenv("IMG"); img != "" {
		return img
	}
	return defaultProjectImage
}

func createNamespace(ns string) {
	cmd := exec.Command("kubectl", "create", "ns", ns, "--dry-run=client", "-o", "yaml")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())

	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(output)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

func deleteNamespace(ns string) {
	cmd := exec.Command("kubectl", "delete", "ns", ns, "--ignore-not-found", "--timeout=30s")
	_, _ = utils.Run(cmd)
}

func cleanupAllResources() {
	resources := []string{"pocketidusers", "pocketidusergroups", "pocketidoidcclients", "pocketidinstances"}

	// Remove finalizers from all resources
	for _, resource := range resources {
		cmd := exec.Command("kubectl", "get", resource, "-A",
			"-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}")
		if output, err := utils.Run(cmd); err == nil && output != "" {
			for _, item := range utils.GetNonEmptyLines(output) {
				ns, name, found := strings.Cut(item, "/")
				if found {
					singularResource := strings.TrimSuffix(resource, "s")
					patchCmd := exec.Command("kubectl", "patch", singularResource, name,
						"-n", ns, "--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
					_, _ = utils.Run(patchCmd)
				}
			}
		}
	}

	// Delete all resources
	for _, resource := range resources {
		cmd := exec.Command("kubectl", "delete", resource, "--all", "-A",
			"--ignore-not-found", "--wait=true", "--timeout=30s")
		_, _ = utils.Run(cmd)
	}

	// Delete test namespaces
	deleteNamespace(instanceNS)
	deleteNamespace(userNS)
}
