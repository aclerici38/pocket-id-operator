package oidcclient

import (
	"context"
	"fmt"
	"sort"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/metrics"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// Since Pocket-ID v2.14.0 a client holds a set of secrets: creating one appends, and a secret only
// stops working when deleted. The operator presents a single credential, so it keeps the secret
// whose value is in the credentials Secret and deletes the rest, holding superseded ones for
// spec.clientSecretOverlap first.
//
// Which secret is the operator's is derived from the stored value, matched against the clear-text
// prefix Pocket-ID records for each secret. status.clientSecretID only breaks a tie between
// secrets sharing a prefix, so a crash between the credentials Secret write and the status write
// cannot cause the secret the cluster is now using to be retired.

type clientSecretRetentionAPI interface {
	DeleteOIDCClientSecret(ctx context.Context, id, secretID string) error
}

type clientSecretRetentionReadAPI interface {
	clientSecretRetentionAPI
	ListOIDCClientSecrets(ctx context.Context, id string) ([]pocketid.OIDCClientSecret, error)
}

func clientSecretOverlap(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) time.Duration {
	if oidcClient.Spec.ClientSecretOverlap == nil {
		return 0
	}
	return oidcClient.Spec.ClientSecretOverlap.Duration
}

// resolveClientSecret identifies the secret holding storedValue, or nil when it cannot be told
// which one that is. Secrets with no prefix predate v2.14.0 and their values were never stored, so
// a lone one is claimed — that is what lets an upgraded client keep its secret instead of rotating.
func resolveClientSecret(statusID, storedValue string, secrets []pocketid.OIDCClientSecret) *pocketid.OIDCClientSecret {
	if storedValue == "" || len(secrets) == 0 {
		return nil
	}

	var byPrefix, byMissingPrefix []pocketid.OIDCClientSecret
	prefix := pocketid.SecretPrefix(storedValue)
	for _, secret := range secrets {
		switch {
		case !secret.IsActive:
			// Expired out-of-band: Pocket-ID rejects it, so it cannot be the live credential.
		case secret.Prefix == "":
			byMissingPrefix = append(byMissingPrefix, secret)
		case prefix != "" && secret.Prefix == prefix:
			byPrefix = append(byPrefix, secret)
		}
	}

	if match := onlyOrStatusMatch(byPrefix, statusID); match != nil {
		return match
	}
	return onlyOrStatusMatch(byMissingPrefix, statusID)
}

// onlyOrStatusMatch returns the sole candidate, or the one status already named. Ambiguity with no
// tie-break yields nil rather than a guess, since naming the wrong secret retires a live credential.
func onlyOrStatusMatch(candidates []pocketid.OIDCClientSecret, statusID string) *pocketid.OIDCClientSecret {
	if len(candidates) == 1 {
		return &candidates[0]
	}
	if statusID == "" {
		return nil
	}
	for i, candidate := range candidates {
		if candidate.ID == statusID {
			return &candidates[i]
		}
	}
	return nil
}

// clientSecretPresent reports whether value could still be one of the client's secrets. Unlike
// resolveClientSecret it tolerates ambiguity, which is what makes it safe to drive a re-push:
// secrets sharing a prefix are unresolvable but present, and re-pushing would add one every
// reconcile.
func clientSecretPresent(value string, secrets []pocketid.OIDCClientSecret) bool {
	prefix := pocketid.SecretPrefix(value)
	for _, secret := range secrets {
		if !secret.IsActive {
			continue
		}
		if secret.Prefix == "" || (prefix != "" && secret.Prefix == prefix) {
			return true
		}
	}
	return false
}

// supersededClientSecrets returns the secrets that are not current, oldest first.
func supersededClientSecrets(current *pocketid.OIDCClientSecret, secrets []pocketid.OIDCClientSecret) []pocketid.OIDCClientSecret {
	superseded := make([]pocketid.OIDCClientSecret, 0, len(secrets))
	for _, secret := range secrets {
		if current != nil && secret.ID == current.ID {
			continue
		}
		superseded = append(superseded, secret)
	}
	sort.SliceStable(superseded, func(i, j int) bool {
		return superseded[i].CreatedAt.Before(superseded[j].CreatedAt)
	})
	return superseded
}

// reconcileClientSecretRetention reduces the client's secret set to the credential in storedValue.
// Callers must reach it only once that value is durably stored.
//
// observed is the set as of this reconcile's client read, which is current unless this reconcile
// minted a secret of its own.
func (r *Reconciler) reconcileClientSecretRetention(
	ctx context.Context,
	oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient,
	apiClient clientSecretRetentionReadAPI,
	observed []pocketid.OIDCClientSecret,
	storedValue string,
	minted bool,
) error {
	if storedValue == "" || oidcClient.Status.ClientID == "" {
		return nil
	}

	secrets := observed
	if minted {
		fresh, err := apiClient.ListOIDCClientSecrets(ctx, oidcClient.Status.ClientID)
		if err != nil {
			return fmt.Errorf("list client secrets: %w", err)
		}
		secrets = fresh
	}

	current := resolveClientSecret(oidcClient.Status.ClientSecretID, storedValue, secrets)
	if current == nil {
		logf.FromContext(ctx).Info("Cannot identify which Pocket-ID secret the stored client secret is; leaving the client's secrets untouched",
			"name", oidcClient.Name, "clientID", oidcClient.Status.ClientID, "held", len(secrets))
		return nil
	}

	r.recordClientSecretID(ctx, oidcClient, current.ID)

	return r.retireSupersededClientSecrets(ctx, oidcClient, apiClient, current, secrets)
}

// retireSupersededClientSecrets deletes every secret other than current. The overlap runs from when
// current was created — the earliest a consumer could have seen it — since the secrets being retired
// are older than the overlap by definition.
func (r *Reconciler) retireSupersededClientSecrets(
	ctx context.Context,
	oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient,
	apiClient clientSecretRetentionAPI,
	current *pocketid.OIDCClientSecret,
	secrets []pocketid.OIDCClientSecret,
) error {
	if current == nil {
		return nil
	}

	superseded := supersededClientSecrets(current, secrets)
	if len(superseded) == 0 {
		return nil
	}

	overlap := clientSecretOverlap(oidcClient)
	if retireAt := current.CreatedAt.Add(overlap); overlap > 0 && time.Now().Before(retireAt) {
		logf.FromContext(ctx).V(1).Info("Holding superseded client secrets for the configured overlap",
			"name", oidcClient.Name, "count", len(superseded), "retireAt", retireAt)
		return nil
	}

	return r.deleteClientSecrets(ctx, oidcClient, apiClient, superseded, "superseded")
}

// makeRoomForClientSecret retires superseded secrets ahead of their overlap when the client has hit
// Pocket-ID's cap, which would reject the secret about to be created. current is never eligible, so
// a live credential the caller could identify survives a create that fails. When it could not be
// identified there is nothing to protect and nothing to lose: the cap has to be cleared either way,
// and the oldest secret is the least likely to be in use.
func (r *Reconciler) makeRoomForClientSecret(
	ctx context.Context,
	oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient,
	apiClient clientSecretRetentionAPI,
	current *pocketid.OIDCClientSecret,
	secrets []pocketid.OIDCClientSecret,
) error {
	if len(secrets) < pocketid.MaxOIDCClientSecrets {
		return nil
	}

	superseded := supersededClientSecrets(current, secrets)
	needed := min(len(secrets)-pocketid.MaxOIDCClientSecrets+1, len(superseded))

	logf.FromContext(ctx).Info("Retiring superseded client secrets early to stay within Pocket-ID's per-client limit",
		"name", oidcClient.Name, "clientID", oidcClient.Status.ClientID, "held", len(secrets), "retiring", needed)

	return r.deleteClientSecrets(ctx, oidcClient, apiClient, superseded[:needed], "cap")
}

func (r *Reconciler) deleteClientSecrets(
	ctx context.Context,
	oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient,
	apiClient clientSecretRetentionAPI,
	secrets []pocketid.OIDCClientSecret,
	reason string,
) error {
	log := logf.FromContext(ctx)
	for _, secret := range secrets {
		if err := apiClient.DeleteOIDCClientSecret(ctx, oidcClient.Status.ClientID, secret.ID); err != nil {
			return fmt.Errorf("retire client secret %s: %w", secret.ID, err)
		}
		metrics.OIDCClientSecretsRetired.WithLabelValues(oidcClient.Namespace, oidcClient.Name, reason).Inc()
		log.Info("Retired superseded client secret",
			"name", oidcClient.Name, "clientID", oidcClient.Status.ClientID, "secretID", secret.ID, "reason", reason)
	}
	return nil
}

// recordClientSecretID notes which secret the credentials Secret mirrors. A failed write is logged
// rather than propagated: nothing reads it but the tie-break, and failing here after the secret was
// created would mint another on the retry.
func (r *Reconciler) recordClientSecretID(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, id string) {
	if oidcClient.Status.ClientSecretID == id {
		return
	}
	base := oidcClient.DeepCopy()
	oidcClient.Status.ClientSecretID = id
	if err := r.Status().Patch(ctx, oidcClient, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to record the client secret ID in status",
			"name", oidcClient.Name, "secretID", id)
	}
}
