//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("PocketIDInstance High Availability", Ordered, func() {
	const name = "ha-instance"

	BeforeAll(func() {
		DeferCleanup(func() {
			_ = deleteObjectAndWait("pocketidinstance", name, instanceNS, 60*time.Second)
			deleteObject("pod", name+"-db", instanceNS)
			deleteObject("service", name+"-db", instanceNS)
		})

		By("deploying the Postgres database the replicas share")
		applyYAML(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
spec:
  containers:
  - name: postgres
    image: docker.io/library/postgres:18-alpine
    env:
    - name: POSTGRES_PASSWORD
      value: postgres
    # Over TCP: the entrypoint's init server listens only on the unix socket, and would pass a socket probe.
    readinessProbe:
      exec:
        command: ["pg_isready", "-U", "postgres", "-h", "127.0.0.1"]
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
  - port: 5432
`, name+"-db", instanceNS))
		waitForReady("pod", name+"-db", instanceNS)

		applyYAML(buildInstanceYAML(InstanceOptions{Name: name}) + fmt.Sprintf(`  replicas: 1
  fileBackend: database
  databaseUrl:
    value: postgres://postgres:postgres@%s-db:5432/postgres?sslmode=disable
`, name))
		waitForReady("pocketidinstance", name, instanceNS)
	})

	// Every step requires all pods Ready without a restart: Francis turns a pod away while one with a
	// different HA_ENABLED runs, which crash-loops it. Each step also checks which pods were kept or
	// replaced, so a drain that is skipped or one that isn't needed both fail.
	var pods []string
	step := func(patch string, n int, kept bool) {
		GinkgoHelper()
		Expect(patchObject("pocketidinstance", name, instanceNS, `{"spec":`+patch+`}`)).To(Succeed())
		pods = waitForHAPods(name, n, kept, pods)
		waitForReady("pocketidinstance", name, instanceNS)
	}

	It("should start a single pod without HA_ENABLED", func() {
		pods = waitForHAPods(name, 1, false, nil)
		Expect(getField("deployment", name, instanceNS, ".spec.strategy.type")).To(Equal("Recreate"))
	})

	It("should stop the single pod before starting 3 HA replicas", func() {
		step(`{"replicas":3}`, 3, false)
	})

	It("should scale down to 2 HA replicas without replacing them", func() {
		step(`{"replicas":2}`, 2, true)
	})

	It("should roll the HA replicas", func() {
		step(`{"annotations":{"e2e/rollout":"1"}}`, 2, false)
	})

	It("should keep a pod when scaling to 1 replica that keeps rolling", func() {
		step(`{"replicas":1,"updateStrategy":"RollingUpdate"}`, 1, true)
	})

	It("should start a single HA pod's replacement before stopping it", func() {
		step(`{"annotations":{"e2e/rollout":"2"}}`, 1, false)
	})

	It("should stop the HA pod before going back to the default Recreate", func() {
		step(`{"updateStrategy":null}`, 1, false)
		Expect(getField("deployment", name, instanceNS, ".spec.strategy.type")).To(Equal("Recreate"))
	})
})

// waitForHAPods waits for exactly n pods of the instance, all Ready without a restart, and returns
// their UIDs. With kept they must all be among prev, otherwise none of them may be.
func waitForHAPods(instance string, n int, kept bool, prev []string) []string {
	GinkgoHelper()
	var uids []string
	Eventually(func(g Gomega) {
		pods := &corev1.PodList{}
		g.Expect(k8sClient.List(context.Background(), pods, client.InNamespace(instanceNS),
			client.MatchingLabels{"app.kubernetes.io/instance": instance})).To(Succeed())
		g.Expect(pods.Items).To(HaveLen(n))
		uids = nil
		for _, pod := range pods.Items {
			g.Expect(pod.Status.ContainerStatuses).To(ConsistOf(
				And(HaveField("Ready", true), HaveField("RestartCount", int32(0)))), pod.Name)
			uids = append(uids, string(pod.UID))
		}
		if kept {
			g.Expect(uids).To(HaveEach(BeElementOf(prev)))
		} else if len(prev) > 0 {
			g.Expect(uids).NotTo(ContainElement(BeElementOf(prev)))
		}
	}, 5*time.Minute).Should(Succeed())
	return uids
}
