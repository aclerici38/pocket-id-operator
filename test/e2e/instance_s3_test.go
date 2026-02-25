//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PocketIDInstance S3 Configuration", Serial, Ordered, func() {
	const s3Instance = "s3-config-test"

	AfterAll(func() {
		kubectlDelete("pocketidinstance", s3Instance, instanceNS)
		kubectlDelete("secret", "s3-test-creds", instanceNS)
	})

	Context("Inline string values", func() {
		const inlineInstance = "s3-inline-test"

		AfterAll(func() {
			kubectlDelete("pocketidinstance", inlineInstance, instanceNS)
		})

		It("should set S3 env vars from inline strings", func() {
			By("creating an instance with S3 config using inline values")
			createInstance(InstanceOptions{
				Name: inlineInstance,
				S3: &S3Options{
					Bucket:         "my-bucket",
					Region:         "us-east-1",
					Endpoint:       "https://s3.example.com",
					AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
					SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					ForcePathStyle: true,
				},
			})

			By("verifying FILE_BACKEND is set to s3")
			Eventually(func(g Gomega) {
				output := kubectlGet("deployment", inlineInstance, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='FILE_BACKEND')].value}")
				g.Expect(output).To(Equal("s3"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying S3_BUCKET env var")
			output := kubectlGet("deployment", inlineInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='S3_BUCKET')].value}")
			Expect(output).To(Equal("my-bucket"))

			By("verifying S3_REGION from inline string")
			output = kubectlGet("deployment", inlineInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='S3_REGION')].value}")
			Expect(output).To(Equal("us-east-1"))

			By("verifying S3_ENDPOINT from inline string")
			output = kubectlGet("deployment", inlineInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='S3_ENDPOINT')].value}")
			Expect(output).To(Equal("https://s3.example.com"))

			By("verifying S3_ACCESS_KEY_ID from inline string")
			output = kubectlGet("deployment", inlineInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='S3_ACCESS_KEY_ID')].value}")
			Expect(output).To(Equal("AKIAIOSFODNN7EXAMPLE"))

			By("verifying S3_SECRET_ACCESS_KEY from inline string")
			output = kubectlGet("deployment", inlineInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='S3_SECRET_ACCESS_KEY')].value}")
			Expect(output).To(Equal("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))

			By("verifying S3_FORCE_PATH_STYLE env var")
			output = kubectlGet("deployment", inlineInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='S3_FORCE_PATH_STYLE')].value}")
			Expect(output).To(Equal("true"))
		})
	})

	Context("Secret reference values", func() {
		It("should set S3 env vars from secret references", func() {
			By("creating a secret with S3 credentials")
			applyYAML(createSecretYAML("s3-test-creds", instanceNS, map[string]string{
				"region":     "eu-west-1",
				"endpoint":   "https://minio.example.com",
				"access-key": "TESTKEY123",
				"secret-key": "TESTSECRET456",
			}))

			By("creating an instance with S3 config using secretKeyRef")
			createInstance(InstanceOptions{
				Name: s3Instance,
				S3: &S3Options{
					Bucket:                   "secret-bucket",
					RegionSecretRef:          &SecretKeyRef{Name: "s3-test-creds", Key: "region"},
					EndpointSecretRef:        &SecretKeyRef{Name: "s3-test-creds", Key: "endpoint"},
					AccessKeyIDSecretRef:     &SecretKeyRef{Name: "s3-test-creds", Key: "access-key"},
					SecretAccessKeySecretRef: &SecretKeyRef{Name: "s3-test-creds", Key: "secret-key"},
				},
			})

			envPath := func(envName, field string) string {
				return fmt.Sprintf("{.spec.template.spec.containers[0].env[?(@.name=='%s')].valueFrom.secretKeyRef.%s}", envName, field)
			}

			By("verifying S3_REGION references the secret")
			Eventually(func(g Gomega) {
				output := kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_REGION", "name")))
				g.Expect(output).To(Equal("s3-test-creds"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			output := kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_REGION", "key")))
			Expect(output).To(Equal("region"))

			By("verifying S3_ENDPOINT references the secret")
			output = kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_ENDPOINT", "name")))
			Expect(output).To(Equal("s3-test-creds"))
			output = kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_ENDPOINT", "key")))
			Expect(output).To(Equal("endpoint"))

			By("verifying S3_ACCESS_KEY_ID references the secret")
			output = kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_ACCESS_KEY_ID", "name")))
			Expect(output).To(Equal("s3-test-creds"))
			output = kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_ACCESS_KEY_ID", "key")))
			Expect(output).To(Equal("access-key"))

			By("verifying S3_SECRET_ACCESS_KEY references the secret")
			output = kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_SECRET_ACCESS_KEY", "name")))
			Expect(output).To(Equal("s3-test-creds"))
			output = kubectlGet("deployment", s3Instance, "-n", instanceNS, "-o", fmt.Sprintf("jsonpath=%s", envPath("S3_SECRET_ACCESS_KEY", "key")))
			Expect(output).To(Equal("secret-key"))

			By("verifying S3_BUCKET is still an inline value")
			output = kubectlGet("deployment", s3Instance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='S3_BUCKET')].value}")
			Expect(output).To(Equal("secret-bucket"))
		})
	})
})
