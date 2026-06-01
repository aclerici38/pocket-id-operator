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

func TestEffectiveAppURL_ExternalEmptyURLFallsBackToAppURL(t *testing.T) {
	// An external config with an empty URL must not shadow the deployed appUrl.
	i := &PocketIDInstance{}
	i.Spec.AppURL = "https://deployed.example.com"
	i.Spec.External = &ExternalInstanceConfig{URL: ""}
	if got := i.EffectiveAppURL(); got != "https://deployed.example.com" {
		t.Errorf("got %q, want %q", got, "https://deployed.example.com")
	}
}

func TestEffectiveAppURL_BothEmpty(t *testing.T) {
	i := &PocketIDInstance{}
	if got := i.EffectiveAppURL(); got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestEffectiveAppURL_ExternalMultipleTrailingSlashes(t *testing.T) {
	i := &PocketIDInstance{}
	i.Spec.External = &ExternalInstanceConfig{URL: "https://auth.example.com///"}
	if got := i.EffectiveAppURL(); got != "https://auth.example.com" {
		t.Errorf("got %q, want %q", got, "https://auth.example.com")
	}
}
