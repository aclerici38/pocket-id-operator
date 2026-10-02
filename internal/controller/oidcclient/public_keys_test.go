package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	keyA = `{"kty":"OKP","crv":"Ed25519","kid":"a","x":"AA"}`
	keyB = `{"kty":"OKP","crv":"Ed25519","kid":"b","x":"BB"}`

	// secretValue stands in for key material that must never appear in an error.
	secretValue = "SECRET-MATERIAL"
	privateKey  = `{"kty":"OKP","crv":"Ed25519","kid":"p","x":"AA","d":"` + secretValue + `"}`
)

func inlineKey(key string) pocketidinternalv1alpha1.OIDCClientPublicKey {
	return pocketidinternalv1alpha1.OIDCClientPublicKey{Value: &apiextensionsv1.JSON{Raw: []byte(key)}}
}

func configMapKey(name, key string, optional bool) pocketidinternalv1alpha1.OIDCClientPublicKey {
	return pocketidinternalv1alpha1.OIDCClientPublicKey{ValueFrom: &pocketidinternalv1alpha1.OIDCClientPublicKeySource{
		ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: name}, Key: key, Optional: ptr.To(optional),
		},
	}}
}

func secretKey(name, key string) pocketidinternalv1alpha1.OIDCClientPublicKey {
	return pocketidinternalv1alpha1.OIDCClientPublicKey{ValueFrom: &pocketidinternalv1alpha1.OIDCClientPublicKeySource{
		SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: name}, Key: key},
	}}
}

func rawKeys(keys ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(keys))
	for i, key := range keys {
		out[i] = json.RawMessage(key)
	}
	return out
}

func TestResolvePublicKeys(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "keys", Namespace: testNamespace},
			Data: map[string]string{
				"jwk":   keyA,
				"jwks":  `{"keys":[` + keyA + `,` + keyB + `]}`,
				"empty": `{"keys":[]}`,
				"mixed": `{"keys":[` + keyA + `,` + privateKey + `]}`,
				"bad":   `not json`,
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "secret-keys", Namespace: testNamespace},
			Data:       map[string][]byte{"jwk": []byte(keyB), "private": []byte(privateKey)},
		},
	).Build()
	r := &Reconciler{APIReader: reader}

	for _, tc := range []struct {
		name    string
		keys    [][]pocketidinternalv1alpha1.OIDCClientPublicKey // per identity
		want    [][]json.RawMessage
		wantErr bool
	}{
		{name: "no keys", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{nil}, want: [][]json.RawMessage{nil}},
		{name: "inline", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{inlineKey(keyA)}}, want: [][]json.RawMessage{rawKeys(keyA)}},
		{name: "ConfigMap JWK", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("keys", "jwk", false)}}, want: [][]json.RawMessage{rawKeys(keyA)}},
		{name: "ConfigMap JWKS", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("keys", "jwks", false)}}, want: [][]json.RawMessage{rawKeys(keyA, keyB)}},
		{name: "Secret JWK", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{secretKey("secret-keys", "jwk")}}, want: [][]json.RawMessage{rawKeys(keyB)}},
		{
			name: "entries concatenate per identity",
			keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{
				{inlineKey(keyB), configMapKey("keys", "jwk", false)},
				{secretKey("secret-keys", "jwk")},
			},
			want: [][]json.RawMessage{rawKeys(keyB, keyA), rawKeys(keyB)},
		},
		{
			name: "missing optional reference holds no keys",
			keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("absent", "jwk", true), configMapKey("keys", "absent", true), inlineKey(keyA)}},
			want: [][]json.RawMessage{rawKeys(keyA)},
		},
		{name: "missing ConfigMap", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("absent", "jwk", false)}}, wantErr: true},
		{name: "missing Secret", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{secretKey("absent", "jwk")}}, wantErr: true},
		{name: "missing key", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("keys", "absent", false)}}, wantErr: true},
		{name: "not JSON", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("keys", "bad", false)}}, wantErr: true},
		// Pocket-ID would fall back to the issuer's JWKS URL for an identity left with no keys.
		{name: "empty JWKS", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("keys", "empty", false)}}, wantErr: true},
		{name: "only missing optional references", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("absent", "jwk", true)}}, wantErr: true},
		// Secret material must not leave the cluster, even though Pocket-ID would reject it.
		{name: "private key in Secret", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{secretKey("secret-keys", "private")}}, wantErr: true},
		{name: "private key in JWKS", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{configMapKey("keys", "mixed", false)}}, wantErr: true},
		{name: "inline symmetric key", keys: [][]pocketidinternalv1alpha1.OIDCClientPublicKey{{inlineKey(`{"kty":"oct","kid":"s","k":"` + secretValue + `"}`)}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testNamespace}}
			identities := make([]pocketid.OIDCClientFederatedIdentity, len(tc.keys))
			for _, keys := range tc.keys {
				oidcClient.Spec.FederatedIdentities = append(oidcClient.Spec.FederatedIdentities,
					pocketidinternalv1alpha1.OIDCClientFederatedIdentity{Issuer: "https://issuer.example.com", PublicKeys: keys})
			}

			err := r.resolvePublicKeys(context.Background(), oidcClient, identities)
			if tc.wantErr {
				if !errors.Is(err, errPublicKeys) {
					t.Fatalf("expected a public key error, got %v", err)
				}
				if got := reconcileErrorReason(err); got != "PublicKeyError" {
					t.Errorf("reason = %q, want PublicKeyError", got)
				}
				if strings.Contains(err.Error(), secretValue) {
					t.Errorf("error leaks key material: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePublicKeys: %v", err)
			}
			for i, identity := range identities {
				if !reflect.DeepEqual(identity.PublicKeys, tc.want[i]) {
					t.Errorf("identity %d keys = %s, want %s", i, identity.PublicKeys, tc.want[i])
				}
			}
		})
	}
}
