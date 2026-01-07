//go:build e2e
// +build e2e

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"io"
	"os/exec"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
)

const (
	namespace    = "pocket-id-operator-system"
	projectImage = "pocket-id-operator:e2e"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	SetDefaultEventuallyTimeout(3 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)
	RunSpecs(t, "Pocket-ID Operator E2E Suite")
}

var _ = BeforeSuite(func() {
	By("building the operator image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to build operator image")

	By("loading the operator image into Kind")
	err = utils.LoadImageToKindClusterWithName(projectImage)
	Expect(err).NotTo(HaveOccurred(), "Failed to load operator image into Kind")

	By("cleaning up any resources from previous runs")
	cleanupAllResources()

	By("installing CRDs")
	cmd = exec.Command("make", "install")
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

	By("deploying the operator")
	cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
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
})

var _ = AfterSuite(func() {
	By("cleaning up all test resources")
	cleanupAllResources()

	By("undeploying the operator")
	cmd := exec.Command("make", "undeploy", "--ignore-errors")
	_, _ = utils.Run(cmd)

	By("uninstalling CRDs")
	cmd = exec.Command("make", "uninstall", "--ignore-errors")
	_, _ = utils.Run(cmd)
})

func cleanupAllResources() {
	// Remove finalizers from all PocketIDUsers first
	cmd := exec.Command("kubectl", "get", "pocketidusers", "-A",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}")
	if output, err := utils.Run(cmd); err == nil && output != "" {
		for _, item := range utils.GetNonEmptyLines(output) {
			parts := splitNamespacedName(item)
			if len(parts) == 2 {
				patchCmd := exec.Command("kubectl", "patch", "pocketiduser", parts[1],
					"-n", parts[0], "--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
				_, _ = utils.Run(patchCmd)
			}
		}
	}

	// Remove finalizers from all PocketIDInstances
	cmd = exec.Command("kubectl", "get", "pocketidinstances", "-A",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}")
	if output, err := utils.Run(cmd); err == nil && output != "" {
		for _, item := range utils.GetNonEmptyLines(output) {
			parts := splitNamespacedName(item)
			if len(parts) == 2 {
				patchCmd := exec.Command("kubectl", "patch", "pocketidinstance", parts[1],
					"-n", parts[0], "--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
				_, _ = utils.Run(patchCmd)
			}
		}
	}

	// Delete all PocketIDUsers
	cmd = exec.Command("kubectl", "delete", "pocketidusers", "--all", "-A",
		"--ignore-not-found", "--wait=true", "--timeout=30s")
	_, _ = utils.Run(cmd)

	// Delete all PocketIDInstances
	cmd = exec.Command("kubectl", "delete", "pocketidinstances", "--all", "-A",
		"--ignore-not-found", "--wait=true", "--timeout=30s")
	_, _ = utils.Run(cmd)

	// Also delete any test namespaces from previous runs
	cmd = exec.Command("kubectl", "delete", "ns", "pocket-id-e2e-test",
		"--ignore-not-found", "--timeout=30s")
	_, _ = utils.Run(cmd)
}

func splitNamespacedName(s string) []string {
	var parts []string
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			parts = append(parts, s[:i])
			parts = append(parts, s[i+1:])
			return parts
		}
	}
	return parts
}

func stringReader(s string) *stringReaderImpl {
	return &stringReaderImpl{s: s, i: 0}
}

type stringReaderImpl struct {
	s string
	i int
}

func (r *stringReaderImpl) Read(p []byte) (n int, err error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}
