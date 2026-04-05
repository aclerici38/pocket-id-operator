package instance

import (
	"testing"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

func TestHasAppConfigFields(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*pocketidinternalv1alpha1.PocketIDInstance)
		expected bool
	}{
		{
			name:     "no config sections",
			modify:   func(_ *pocketidinternalv1alpha1.PocketIDInstance) {},
			expected: false,
		},
		{
			name:     "UI set",
			modify:   func(i *pocketidinternalv1alpha1.PocketIDInstance) { i.Spec.UI = &pocketidinternalv1alpha1.UIConfig{} },
			expected: true,
		},
		{
			name: "SMTP set",
			modify: func(i *pocketidinternalv1alpha1.PocketIDInstance) {
				i.Spec.SMTP = &pocketidinternalv1alpha1.SMTPConfig{Host: "h", Port: 25, From: "f"}
			},
			expected: true,
		},
		{
			name: "LDAP set",
			modify: func(i *pocketidinternalv1alpha1.PocketIDInstance) {
				i.Spec.LDAP = &pocketidinternalv1alpha1.LDAPConfig{URL: "u", BindDN: "d", Base: "b",
					BindPassword: pocketidinternalv1alpha1.SensitiveValue{Value: "p"}}
			},
			expected: true,
		},
		{
			name:     "UserManagement set",
			modify:   func(i *pocketidinternalv1alpha1.PocketIDInstance) { i.Spec.UserManagement = &pocketidinternalv1alpha1.UserManagementConfig{} },
			expected: true,
		},
		{
			name:     "EmailNotifications set",
			modify:   func(i *pocketidinternalv1alpha1.PocketIDInstance) { i.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{} },
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inst := minimalInstance()
			tc.modify(inst)
			if got := hasAppConfigFields(inst); got != tc.expected {
				t.Errorf("hasAppConfigFields() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestAppConfigNeedsUpdate_NoChange(t *testing.T) {
	current := pocketid.AppConfig{
		"appName":        "Pocket ID",
		"sessionDuration": "60",
		"smtpHost":       "smtp.example.com",
		"ldapEnabled":    "false",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AppName:         strPtr("Pocket ID"),
		SessionDuration: strPtr("60"),
		SMTPHost:        "smtp.example.com",
		LdapEnabled:     strPtr("false"),
	}

	if appConfigNeedsUpdate(current, dto) {
		t.Error("expected no update needed when values match")
	}
}

func TestAppConfigNeedsUpdate_Changed(t *testing.T) {
	current := pocketid.AppConfig{
		"appName":        "Pocket ID",
		"sessionDuration": "60",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AppName:         strPtr("My SSO"),
		SessionDuration: strPtr("60"),
	}

	if !appConfigNeedsUpdate(current, dto) {
		t.Error("expected update needed when appName changed")
	}
}

func TestAppConfigNeedsUpdate_SMTPChanged(t *testing.T) {
	current := pocketid.AppConfig{
		"smtpHost": "old.example.com",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		SMTPHost: "new.example.com",
	}

	if !appConfigNeedsUpdate(current, dto) {
		t.Error("expected update needed when smtpHost changed")
	}
}

func TestAppConfigNeedsUpdate_LDAPChanged(t *testing.T) {
	current := pocketid.AppConfig{
		"ldapEnabled": "false",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		LdapEnabled: strPtr("true"),
	}

	if !appConfigNeedsUpdate(current, dto) {
		t.Error("expected update needed when ldapEnabled changed")
	}
}
