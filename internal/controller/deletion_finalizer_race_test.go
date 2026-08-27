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

package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/controller/oidcclient"
	"github.com/aclerici38/pocket-id-operator/internal/controller/usergroup"
)

// testHoldFinalizer keeps a deleting object addressable for the duration of a spec, so the
// reconciler under test can be driven against a real "being deleted" object instead of one
// the API server has already reaped.
const testHoldFinalizer = "test.pocketid.internal/hold"

// These specs pin the behaviour behind a CI flake in the e2e suite's "Reference Finalizers"
// context, where a PocketIDOIDCClient was deleted 256ms after the PocketIDUserGroup that
// references it was created. The oidcclient controller runs with MaxConcurrentReconciles: 1,
// so when its queue is busy the cross-reference finalizer has not landed yet when the delete
// arrives — and from that point on it can never land, because Kubernetes forbids adding a
// finalizer to an object that is already being deleted. The reconciler retried the forbidden
// write forever and the object was left undeletable.
//
// A real API server is required: the fake client does not enforce ValidateNoNewFinalizers,
// so this is invisible below envtest.
var _ = Describe("Deleting a resource before its reference finalizer lands", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	// Establishes the root cause on its own terms, independent of this repo's code: once an
	// object is being deleted, no actor can add a finalizer to it. Asserted with a raw Update
	// rather than through helpers.EnsureFinalizer so it keeps pinning the rule that makes the
	// fix necessary, instead of tracking whatever the helper is changed to do.
	It("is rejected by the API server when a finalizer is added after deletion has started", func() {
		By("creating an object that will survive its own deletion")
		held := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "finalizer-race-probe",
				Namespace:  defaultNamespace,
				Finalizers: []string{testHoldFinalizer},
			},
		}
		Expect(k8sClient.Create(ctx, held)).To(Succeed())
		DeferCleanup(func() { releaseTestHold(context.Background(), held) })

		By("requesting deletion so the object carries a deletionTimestamp")
		Expect(k8sClient.Delete(ctx, held)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(held), held)).To(Succeed())
		Expect(held.DeletionTimestamp).NotTo(BeNil())

		By("attempting to add a second finalizer after the fact")
		held.Finalizers = append(held.Finalizers, "test.pocketid.internal/too-late")
		err := k8sClient.Update(ctx, held)

		Expect(err).To(HaveOccurred(),
			"if this passes, the API server no longer rejects new finalizers on a deleting "+
				"object and the ReconcileDelete guard can be reconsidered")
		// The rejection arrives as 422 Invalid carrying a FieldValueForbidden cause, not as
		// a 403, so apierrors.IsForbidden does not match it.
		Expect(apierrors.IsInvalid(err)).To(BeTrue(),
			"expected an Invalid error rejecting the finalizer, got %v", err)
		Expect(err.Error()).To(ContainSubstring("no new finalizers can be added"))
		Expect(apierrors.IsConflict(err)).To(BeFalse(),
			"helpers.EnsureFinalizer swallows Conflict as success, so this rejection must not "+
				"look like one: it is permanent, and retrying it can never succeed")
	})

	// The oidcclient direction: the spec that actually failed in CI.
	It("does not wedge a PocketIDOIDCClient whose user group reference lands after deletion", func() {
		clientName, groupName := "race-oidc-client", "race-oidc-group"

		By("creating an OIDC client that will outlive its deletion request")
		oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
			ObjectMeta: metav1.ObjectMeta{
				Name:       clientName,
				Namespace:  defaultNamespace,
				Finalizers: []string{testHoldFinalizer},
			},
			Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
				CallbackURLs: []string{"https://example.com/callback"},
			},
		}
		Expect(k8sClient.Create(ctx, oidcClient)).To(Succeed())
		DeferCleanup(func() { releaseTestHold(context.Background(), oidcClient) })

		By("deleting it before any user group references it")
		Expect(k8sClient.Delete(ctx, oidcClient)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oidcClient), oidcClient)).To(Succeed())
			g.Expect(oidcClient.DeletionTimestamp).NotTo(BeNil())
		}).Should(Succeed())

		By("creating the referencing user group only now, so the reference is observed too late")
		group := &pocketidinternalv1alpha1.PocketIDUserGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:       groupName,
				Namespace:  defaultNamespace,
				Finalizers: []string{testHoldFinalizer},
			},
			Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
				Name:               groupName,
				FriendlyName:       "Race Group",
				AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: clientName}},
			},
		}
		Expect(k8sClient.Create(ctx, group)).To(Succeed())
		DeferCleanup(func() { releaseTestHold(context.Background(), group) })

		reconciler := &oidcclient.Reconciler{
			Client:         k8sClient,
			BaseReconciler: common.BaseReconciler{Client: k8sClient, APIReader: k8sClient},
			APIReader:      k8sClient,
			Scheme:         k8sClient.Scheme(),
		}

		By("confirming the reconciler does take the deletion-blocked branch")
		// Without this the next assertion could pass vacuously, by never reaching the
		// finalizer write at all.
		Eventually(func(g Gomega) string {
			fresh := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oidcClient), fresh)).To(Succeed())
			_, _ = reconciler.ReconcileDelete(ctx, fresh)

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oidcClient), updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			g.Expect(cond).NotTo(BeNil())
			return cond.Reason
		}).Should(Equal("DeletionBlocked"))

		By("requiring every delete reconcile to make progress rather than erroring forever")
		// Consistently rather than Eventually: the bug is a permanent failure, so a single
		// passing call proves nothing — a concurrent write from the running manager can turn
		// one call into a Conflict, which EnsureFinalizer reports as success.
		Consistently(func(g Gomega) {
			fresh := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oidcClient), fresh)).To(Succeed())
			g.Expect(fresh.DeletionTimestamp).NotTo(BeNil())

			_, err := reconciler.ReconcileDelete(ctx, fresh)
			g.Expect(err).NotTo(HaveOccurred(),
				"ReconcileDelete must block deletion without attempting a write the API "+
					"server can never accept; retrying it leaves the object undeletable")
		}, 3*time.Second, 250*time.Millisecond).Should(Succeed())
	})

	// The same three lines exist in usergroup, user and api. This covers the second half of
	// the e2e context that flaked, and proves the fix has to be applied per controller.
	It("does not wedge a PocketIDUserGroup whose OIDC client reference lands after deletion", func() {
		clientName, groupName := "race-rev-oidc-client", "race-rev-group"

		By("creating a user group that will outlive its deletion request")
		group := &pocketidinternalv1alpha1.PocketIDUserGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:       groupName,
				Namespace:  defaultNamespace,
				Finalizers: []string{testHoldFinalizer},
			},
			Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
				Name:         groupName,
				FriendlyName: "Race Rev Group",
			},
		}
		Expect(k8sClient.Create(ctx, group)).To(Succeed())
		DeferCleanup(func() { releaseTestHold(context.Background(), group) })

		By("deleting it before any OIDC client references it")
		Expect(k8sClient.Delete(ctx, group)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(group), group)).To(Succeed())
			g.Expect(group.DeletionTimestamp).NotTo(BeNil())
		}).Should(Succeed())

		By("creating the referencing OIDC client only now")
		oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
			ObjectMeta: metav1.ObjectMeta{
				Name:       clientName,
				Namespace:  defaultNamespace,
				Finalizers: []string{testHoldFinalizer},
			},
			Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
				CallbackURLs:      []string{"https://example.com/callback"},
				AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: groupName}},
			},
		}
		Expect(k8sClient.Create(ctx, oidcClient)).To(Succeed())
		DeferCleanup(func() { releaseTestHold(context.Background(), oidcClient) })

		reconciler := &usergroup.Reconciler{
			Client:         k8sClient,
			BaseReconciler: common.BaseReconciler{Client: k8sClient, APIReader: k8sClient},
			APIReader:      k8sClient,
			Scheme:         k8sClient.Scheme(),
		}

		By("confirming the reconciler does take the deletion-blocked branch")
		Eventually(func(g Gomega) string {
			fresh := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(group), fresh)).To(Succeed())
			_, _ = reconciler.ReconcileDelete(ctx, fresh)

			updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(group), updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			g.Expect(cond).NotTo(BeNil())
			return cond.Reason
		}).Should(Equal("DeletionBlocked"))

		By("requiring every delete reconcile to make progress rather than erroring forever")
		Consistently(func(g Gomega) {
			fresh := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(group), fresh)).To(Succeed())
			g.Expect(fresh.DeletionTimestamp).NotTo(BeNil())

			_, err := reconciler.ReconcileDelete(ctx, fresh)
			g.Expect(err).NotTo(HaveOccurred(),
				"ReconcileDelete must block deletion without attempting a write the API "+
					"server can never accept; retrying it leaves the object undeletable")
		}, 3*time.Second, 250*time.Millisecond).Should(Succeed())
	})
})

// releaseTestHold drops the hold finalizer and lets the object be reaped, so a deleting
// object left behind by one spec cannot show up in another spec's cluster-wide reference
// scan. It tolerates an object that is already gone.
func releaseTestHold(ctx context.Context, obj client.Object) {
	GinkgoHelper()
	key := client.ObjectKeyFromObject(obj)
	Eventually(func() error {
		if err := k8sClient.Get(ctx, key, obj); err != nil {
			return client.IgnoreNotFound(err)
		}
		if controllerutil.RemoveFinalizer(obj, testHoldFinalizer) {
			if err := k8sClient.Update(ctx, obj); err != nil {
				return client.IgnoreNotFound(err)
			}
		}
		if obj.GetDeletionTimestamp() == nil {
			return client.IgnoreNotFound(k8sClient.Delete(ctx, obj))
		}
		return nil
	}).Should(Succeed())
}
