package v1alpha1

import "testing"

func TestEffectiveAppURL_DeployedStripsTrailingSlash(t *testing.T) {
	i := &PocketIDInstance{}
	i.Spec.AppURL = "https://id.example.com/"
	if got := i.EffectiveAppURL(); got != "https://id.example.com" {
		t.Errorf("got %q, want %q", got, "https://id.example.com")
	}
}

func TestEffectiveAppURL_ExternalStripsTrailingSlash(t *testing.T) {
	i := &PocketIDInstance{}
	i.Spec.External = &ExternalInstanceConfig{URL: "https://auth.example.com/"}
	if got := i.EffectiveAppURL(); got != "https://auth.example.com" {
		t.Errorf("got %q, want %q", got, "https://auth.example.com")
	}
}

func TestEffectiveAppURL_ExternalPrefersOverAppURL(t *testing.T) {
	i := &PocketIDInstance{}
	i.Spec.AppURL = "https://deployed.example.com"
	i.Spec.External = &ExternalInstanceConfig{URL: "https://auth.example.com"}
	if got := i.EffectiveAppURL(); got != "https://auth.example.com" {
		t.Errorf("got %q, want %q", got, "https://auth.example.com")
	}
}

func TestEffectiveAppURL_NoTrailingSlash(t *testing.T) {
	i := &PocketIDInstance{}
	i.Spec.AppURL = "https://id.example.com"
	if got := i.EffectiveAppURL(); got != "https://id.example.com" {
		t.Errorf("got %q, want %q", got, "https://id.example.com")
	}
}
