//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-operator/test/utils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	defaultProjectImage = "pocket-id-operator:e2e"
	namespace           = "pocket-id-operator-system"

	// defaultPocketIDNodePort is the fallback when POCKET_ID_NODE_PORT is unset, and must
	// stay equal to the default in .mise.toml so running ginkgo directly behaves the same
	// as running it through mise.
	defaultPocketIDNodePort = 31411
)

var projectImage = defaultProjectImage

var (
	// k8sClient talks to the Kind cluster with typed objects, replacing jsonpath strings
	// parsed out of kubectl's stdout.
	k8sClient client.Client

	// clientSet backs the one read the typed client cannot do: pod logs.
	clientSet *kubernetes.Clientset

	// pid is the Pocket-ID API client for the shared instance, reached over the published
	// NodePort. It is the same client the operator uses, so the suite exercises the real
	// code path rather than a shell reimplementation of it.
	pid *pocketid.Client
)

// pocketIDNodePort is the host port the shared instance is published on. It is read from
// the same variable setup-test-e2e uses to build the Kind port mapping, so an override
// cannot leave the mapping and this client pointing at different ports.
var pocketIDNodePort = resolvePocketIDNodePort()

func resolvePocketIDNodePort() int {
	raw := os.Getenv("POCKET_ID_NODE_PORT")
	if raw == "" {
		return defaultPocketIDNodePort
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		panic(fmt.Sprintf("POCKET_ID_NODE_PORT=%q is not a number; it has to be the port "+
			"setup-test-e2e publishes from the Kind node", raw))
	}
	return port
}

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
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	clientSet = cs

	return client.New(cfg, client.Options{Scheme: scheme.Scheme})
}

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	// One place to tune the suite's timing. Specs no longer pass their own timeout and
	// interval: 2 minutes matches what the overwhelming majority used, and polling at
	// 250ms costs one extra API GET per tick against a local apiserver while removing
	// most of the observation lag between a condition becoming true and a spec seeing it.
	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(250 * time.Millisecond)
	// Consistently keeps its dwell time at each call site, because there the duration is
	// the assertion; only its polling rate comes from here.
	SetDefaultConsistentlyPollingInterval(250 * time.Millisecond)
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
		deployment := &appsv1.Deployment{}
		g.Expect(k8sClient.Get(context.Background(),
			client.ObjectKey{Name: "pocket-id-operator", Namespace: namespace}, deployment)).To(Succeed())
		g.Expect(deployment.Status.AvailableReplicas).To(BeNumerically(">=", 1),
			"the operator deployment should have an available replica")
	}).Should(Succeed())

	By("creating test namespaces")
	createNamespace(instanceNS)
	createNamespace(userNS)

	By("creating encryption key secret")
	applyYAML(createSecretYAML("pocket-id-encryption", instanceNS, map[string]string{
		"key": "e2e-test-encryption-key-32chars!",
	}))

	By("creating the shared e2e instance")
	// The CIMD allowlist is set on the shared instance rather than a dedicated one because
	// Labelled so every resource can name it explicitly. SelectInstance lists instances
	// cluster-wide and rejects an ambiguous match, so this label is what lets a spec bring
	// up its own instance without breaking everyone else's reconciles.
	createInstance(InstanceOptions{
		Labels:           sharedInstanceLabels,
		CIMDURLAllowlist: []string{cimdMetadataURL},
		NodePort:         pocketIDNodePort,
	})

	By("waiting for the shared instance to be Ready")
	Eventually(func(g Gomega) {
		output := getField("pocketidinstance", instanceName, instanceNS, ".status.conditions[?(@.type=='Ready')].status")
		g.Expect(output).To(Equal("True"))
	}).Should(Succeed())

	actualImage := getFieldBySelector("pod", instanceNS, "app.kubernetes.io/name=pocket-id", ".spec.containers[0].image")
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
	}).Should(Succeed(),
		"Pocket-ID should be reachable on the published NodePort")
})

// staticAPIKey reads the shared instance's static API key, which the operator generates and
// stores alongside the instance. Deliberately read per call rather than cached: the
// regenerate-on-delete spec in instance_test.go replaces this token mid-suite, and a Get
// against the local apiserver is far cheaper than the staleness it would otherwise invite.
func staticAPIKey() string {
	return secretData(instanceName+"-static-api-key", instanceNS, "token")
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
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
	err := k8sClient.Create(context.Background(), namespace)
	if apierrors.IsAlreadyExists(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred(), "creating namespace %s", ns)
}

func deleteNamespace(ns string) {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
	_ = k8sClient.Delete(context.Background(), namespace)
}

func cleanupAllResources() {
	resources := []string{
		"pocketiduser", "pocketidusergroup", "pocketidoidcclient", "pocketidapi", "pocketidinstance",
	}

	// Clear finalizers first: a controller that is itself being torn down would otherwise
	// leave these objects stuck in Terminating and stall the next run.
	for _, resource := range resources {
		list := &unstructured.UnstructuredList{}
		gvk := resourceGVK[resource]
		gvk.Kind += "List"
		list.SetGroupVersionKind(gvk)
		if err := k8sClient.List(context.Background(), list); err != nil {
			continue
		}
		for i := range list.Items {
			item := &list.Items[i]
			_ = patchObject(resource, item.GetName(), item.GetNamespace(),
				`{"metadata":{"finalizers":null}}`)
			_ = k8sClient.Delete(context.Background(), item)
		}
	}

	// Delete test namespaces
	deleteNamespace(instanceNS)
	deleteNamespace(userNS)
}
