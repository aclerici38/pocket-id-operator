package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"
	"github.com/oapi-codegen/nullable"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// errPublicKeys marks a federated identity whose public keys could not be resolved.
var errPublicKeys = errors.New("federated identity public keys")

// secretKeyMembers are the JWK members that carry private or symmetric key material (RFC 7518 §6).
var secretKeyMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// federatedIdentities builds the spec's federated identities, resolving their public keys. It is
// nil when there are none. Pocket-ID validates the keys and names the offending one in its
// error, but a key carrying secret material is refused here.
func (r *Reconciler) federatedIdentities(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) ([]pid.OIDCClientFederatedIdentityInputDto, error) {
	var identities []pid.OIDCClientFederatedIdentityInputDto
	for i, identity := range oidcClient.Spec.FederatedIdentities {
		var publicKeys []any
		for j, source := range identity.PublicKeys {
			keys, err := r.publicKeys(ctx, oidcClient.Namespace, source)
			if err == nil {
				err = checkNoSecretMaterial(keys)
			}
			if err != nil {
				return nil, fmt.Errorf("%w: federatedIdentities[%d].publicKeys[%d]: %w", errPublicKeys, i, j, err)
			}
			for _, key := range keys {
				publicKeys = append(publicKeys, key)
			}
		}
		// Without keys Pocket-ID falls back to the issuer's JWKS URL, which is not what was asked for.
		if len(identity.PublicKeys) > 0 && len(publicKeys) == 0 {
			return nil, fmt.Errorf("%w: federatedIdentities[%d] resolved to no public keys", errPublicKeys, i)
		}
		identities = append(identities, pid.OIDCClientFederatedIdentityInputDto{
			Issuer:           &identity.Issuer,
			Subject:          &identity.Subject,
			Audience:         &identity.Audience,
			JWKS:             &identity.JWKS,
			PublicKeys:       nullable.NewNullableWithValue(publicKeys),
			ReplayProtection: &identity.ReplayProtection,
		})
	}
	return identities, nil
}

// publicKeys returns the keys one spec entry holds. A referenced document may be a single JWK or
// a JWKS, so an issuer publishing a new key during rotation needs no change to the resource.
// References are read uncached, since the cache only holds operator-managed Secrets.
func (r *Reconciler) publicKeys(ctx context.Context, namespace string, source pocketidinternalv1alpha1.OIDCClientPublicKey) ([]json.RawMessage, error) {
	if source.Value != nil {
		return []json.RawMessage{source.Value.Raw}, nil
	}

	if ref := source.ValueFrom.ConfigMapKeyRef; ref != nil {
		cm := &corev1.ConfigMap{}
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, cm)
		document, found := cm.Data[ref.Key]
		return parsePublicKeys(ref.Name, ref.Key, ptr.Deref(ref.Optional, false), err, document, found)
	}
	ref := source.ValueFrom.SecretKeyRef
	secret := &corev1.Secret{}
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, secret)
	document, found := secret.Data[ref.Key]
	return parsePublicKeys(ref.Name, ref.Key, ptr.Deref(ref.Optional, false), err, string(document), found)
}

// parsePublicKeys splits a referenced document into its keys. Optional references are supported.
func parsePublicKeys(name, key string, optional bool, getErr error, document string, found bool) ([]json.RawMessage, error) {
	if getErr != nil {
		if optional && apierrors.IsNotFound(getErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("get %s: %w", name, getErr)
	}
	if !found {
		if optional {
			return nil, nil
		}
		return nil, fmt.Errorf("%s has no key %q", name, key)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal([]byte(document), &jwks); err != nil {
		return nil, fmt.Errorf("%s key %q is not a JWK or JWKS: %w", name, key, err)
	}
	if jwks.Keys != nil {
		return jwks.Keys, nil
	}
	return []json.RawMessage{json.RawMessage(document)}, nil
}

// checkNoSecretMaterial reports a key holding private or symmetric key material.
func checkNoSecretMaterial(keys []json.RawMessage) error {
	for i, key := range keys {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(key, &members); err != nil {
			return fmt.Errorf("key %d is not a JWK: %w", i+1, err)
		}
		for _, member := range secretKeyMembers {
			if _, ok := members[member]; ok {
				return fmt.Errorf("key %d holds secret key material (%q); only public keys may be used", i+1, member)
			}
		}
	}
	return nil
}
