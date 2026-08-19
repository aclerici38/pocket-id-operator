package oidcclient

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

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
// Which secret is the operator's is known outright when this reconcile minted it, and otherwise
// derived from the stored value, matched against the clear-text prefix Pocket-ID records for each
// secret. Nothing else is consulted: any second record of which secret is live would be written
// separately from the credential itself, and the two disagreeing is exactly what would retire the
// secret the cluster is using.

type clientSecretRetentionAPI interface {
	DeleteOIDCClientSecret(ctx context.Context, id, secretID string) error
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
//
// Two secrets sharing a prefix are indistinguishable here, and the caller is told so rather than
// given a guess: retiring the wrong one destroys the live credential, and the prefix that made
// them ambiguous would then match the survivor, so no later reconcile could even detect it.
func resolveClientSecret(storedValue string, secrets []pocketid.OIDCClientSecret) *pocketid.OIDCClientSecret {
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

	// A prefix match is authoritative, so the prefixless secrets are only a fallback for the
	// upgrade case where nothing carries a prefix at all.
	candidates := byPrefix
	if len(candidates) == 0 {
		candidates = byMissingPrefix
	}
	if len(candidates) != 1 {
		return nil
	}
	return &candidates[0]
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
// observed is the set as of this reconcile's client read; minted is the secret this reconcile
// added to it, or nil. Creating a secret is the one moment the operator knows which one is its
// own, so a mint is taken at its word instead of being matched back by prefix.
func (r *Reconciler) reconcileClientSecretRetention(
	ctx context.Context,
	oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient,
	apiClient clientSecretRetentionAPI,
	observed []pocketid.OIDCClientSecret,
	minted *pocketid.OIDCClientSecret,
	storedValue string,
) error {
	if storedValue == "" || oidcClient.Status.ClientID == "" {
		return nil
	}

	secrets, current := observed, minted
	if minted == nil {
		current = resolveClientSecret(storedValue, secrets)
	} else {
		secrets = append(slices.Clone(observed), *minted)
	}
	if current == nil {
		logf.FromContext(ctx).Info("Cannot identify which Pocket-ID secret the stored client secret is; leaving the client's secrets untouched",
			"name", oidcClient.Name, "clientID", oidcClient.Status.ClientID, "held", len(secrets))
		return nil
	}

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
