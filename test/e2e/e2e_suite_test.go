//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-operator/test/utils"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	defaultProjectImage = "pocket-id-operator:e2e"
	namespace           = "pocket-id-operator-system"

	// pocketIDNodePort must match POCKET_ID_NODE_PORT in .mise.toml, which maps it from
	// the Kind node to the same port on the host. The shared instance publishes its http
	// port here so the suite can reach Pocket-ID's API over localhost.
	pocketIDNodePort = 31411
)

var projectImage = defaultProjectImage

var (
	// k8sClient talks to the Kind cluster with typed objects, replacing jsonpath strings
	// parsed out of kubectl's stdout.
	k8sClient client.Client

	// pid is the Pocket-ID API client for the shared instance, reached over the published
	// NodePort. It is the same client the operator uses, so the suite exercises the real
	// code path rather than a shell reimplementation of it.
	pid *pocketid.Client
)

// pocketIDBaseURL is the shared instance's API address as seen from the test binary.
func pocketIDBaseURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", pocketIDNodePort)
}

// newK8sClient builds a typed client against whatever kubeconfig kubectl would use.
func newK8sClient() (client.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, err
	}
	if err := pocketidv1alpha1.AddToScheme(scheme.Scheme); err != nil {
		return nil, err
	}
	if err := gatewayv1.Install(scheme.Scheme); err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{Scheme: scheme.Scheme})
}

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	SetDefaultEventuallyTimeout(3 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)
	RunSpecs(t, "Pocket-ID Operator E2E Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	// This runs only on process 1
	projectImage = resolveProjectImage()
	imgProvided := os.Getenv("IMG") != ""
	// Subprocess mise tasks (docker-build, deploy-e2e) read the image from IMG.
	Expect(os.Setenv("IMG", projectImage)).To(Succeed())

	By("building the operator image")
	if !imgProvided {
		cmd := exec.Command("mise", "run", "docker-build")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to build operator image")
	} else {
		By("skipping build because IMG is set")
	}

	By("loading the operator image into Kind")
	err := utils.LoadImageToKindClusterWithName(projectImage)
	Expect(err).NotTo(HaveOccurred(), "Failed to load operator image into Kind")

	By("building the Kubernetes client")
	var kErr error
	k8sClient, kErr = newK8sClient()
	Expect(kErr).NotTo(HaveOccurred(), "Failed to build Kubernetes client")

	if os.Getenv("SKIP_CLEANUP") == "" {
		By("cleaning up any resources from previous runs")
		cleanupAllResources()
	}

	By("installing CRDs")
	cmd := exec.Command("mise", "run", "install")
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

	By("deploying the operator with e2e config (faster resync)")
	cmd = exec.Command("mise", "run", "deploy-e2e")
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
	// The CIMD allowlist is set on the shared instance rather than a dedicated one because
	// SelectInstance rejects a selector matching more than one PocketIDInstance, so a
	// long-lived second instance would break every client that omits instanceSelector.
	createInstance(InstanceOptions{
		CIMDURLAllowlist: []string{cimdMetadataURL},
		NodePort:         pocketIDNodePort,
	})

	By("waiting for the shared instance to be Ready")
	Eventually(func(g Gomega) {
		output := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		g.Expect(output).To(Equal("True"))
	}, 5*time.Minute, 5*time.Second).Should(Succeed())

	actualImage := kubectlGet("pod", "-n", instanceNS, "-l", "app.kubernetes.io/name=pocket-id",
		"-o", "jsonpath={.items[0].spec.containers[0].image}")
	By(fmt.Sprintf("pocket-id pod is running image: %s", actualImage))

	return nil
}, func(_ []byte) {
	// This runs on all processes
	projectImage = resolveProjectImage()

	var err error
	k8sClient, err = newK8sClient()
	Expect(err).NotTo(HaveOccurred(), "Failed to build Kubernetes client")

	// The NodePort is a fixed address, so each parallel process builds an identical
	// client and there is nothing to hand across from process 1.
	pid, err = pocketid.NewClient(pocketIDBaseURL(), staticAPIKey())
	Expect(err).NotTo(HaveOccurred(), "Failed to build Pocket-ID client")

	Eventually(func() error {
		_, vErr := pid.GetCurrentVersion(context.Background())
		return vErr
	}, 2*time.Minute, 2*time.Second).Should(Succeed(),
		"Pocket-ID should be reachable on the published NodePort")
})

// staticAPIKey reads the shared instance's static API key, which the operator generates
// and stores alongside the instance.
func staticAPIKey() string {
	return kubectlGetSecretData(instanceName+"-static-api-key", instanceNS, "token")
}

var _ = SynchronizedAfterSuite(func() {
	// This runs on all processes
}, func() {
	// This runs only on process 1
	if os.Getenv("SKIP_CLEANUP") != "" {
		By("skipping cleanup because SKIP_CLEANUP is set")
		return
	}

	By("cleaning up test namespace resources")
	removeFinalizers(userNS)
	removeFinalizers(instanceNS)

	By("deleting test namespaces")
	deleteNamespace(userNS)
	deleteNamespace(instanceNS)

	By("cleaning up all resources")
	cleanupAllResources()

	By("undeploying the operator")
	cmd := exec.Command("mise", "run", "undeploy")
	_, _ = utils.Run(cmd)

	By("uninstalling CRDs")
	cmd = exec.Command("mise", "run", "uninstall")
	_, _ = utils.Run(cmd)
})

func resolveProjectImage() string {
	if img := os.Getenv("IMG"); img != "" {
		return img
	}
	return defaultProjectImage
}

func gatewayAPIHTTPRouteCRDPath() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api")
	output, err := utils.Run(cmd)
	if err != nil {
		return "", err
	}

	moduleDir := strings.TrimSpace(output)
	if moduleDir == "" {
		return "", fmt.Errorf("gateway-api module directory is empty")
	}

	return filepath.Join(moduleDir, "config", "crd", "standard", "gateway.networking.k8s.io_httproutes.yaml"), nil
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
	resources := []string{"pocketidusers", "pocketidusergroups", "pocketidoidcclients", "pocketidapis", "pocketidinstances"}

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
