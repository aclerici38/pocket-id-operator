package instance

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/utils/ptr"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// test sentinel values used across table-driven tests
const (
	testNewValue = "new"
	testTrueStr  = "true"
	testFalseStr = "false"
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
			name: "UserManagement set",
			modify: func(i *pocketidinternalv1alpha1.PocketIDInstance) {
				i.Spec.UserManagement = &pocketidinternalv1alpha1.UserManagementConfig{}
			},
			expected: true,
		},
		{
			name: "EmailNotifications set",
			modify: func(i *pocketidinternalv1alpha1.PocketIDInstance) {
				i.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{}
			},
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

// --- appConfigNeedsUpdate tests ---

func TestAppConfigNeedsUpdate_NoChange(t *testing.T) {
	current := pocketid.AppConfig{
		"appName":         "Pocket ID",
		"sessionDuration": "60",
		"smtpHost":        "smtp.example.com",
		"ldapEnabled":     "false",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AppName:         ptr.To("Pocket ID"),
		SessionDuration: ptr.To("60"),
		SMTPHost:        "smtp.example.com",
		LdapEnabled:     ptr.To("false"),
	}

	if appConfigNeedsUpdate(current, dto) {
		t.Error("expected no update needed when values match")
	}
}

func TestAppConfigNeedsUpdate_Changed(t *testing.T) {
	current := pocketid.AppConfig{
		"appName":         "Pocket ID",
		"sessionDuration": "60",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AppName:         ptr.To("My SSO"),
		SessionDuration: ptr.To("60"),
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
		LdapEnabled: ptr.To("true"),
	}

	if !appConfigNeedsUpdate(current, dto) {
		t.Error("expected update needed when ldapEnabled changed")
	}
}

func TestAppConfigNeedsUpdate_NilPtrFieldSkipped(t *testing.T) {
	current := pocketid.AppConfig{
		"appName": "Pocket ID",
	}

	// AppName is nil in desired — should not trigger an update
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}

	if appConfigNeedsUpdate(current, dto) {
		t.Error("expected no update when desired ptr field is nil")
	}
}

func TestAppConfigNeedsUpdate_EmptyCurrentMatchesEmptyDesired(t *testing.T) {
	current := pocketid.AppConfig{}
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}

	if appConfigNeedsUpdate(current, dto) {
		t.Error("expected no update when both current and desired are empty/zero")
	}
}

func TestAppConfigNeedsUpdate_MissingKeyInCurrentDetectsChange(t *testing.T) {
	// Key absent in current (zero value "") vs non-empty desired
	current := pocketid.AppConfig{}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		SMTPHost: "smtp.example.com",
	}

	if !appConfigNeedsUpdate(current, dto) {
		t.Error("expected update when current is missing a key that desired has set")
	}
}

func TestAppConfigNeedsUpdate_EveryPtrField(t *testing.T) {
	type dto = models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto
	ptrFields := []struct {
		key      string
		setField func(*dto)
	}{
		{"appName", func(d *dto) { d.AppName = ptr.To(testNewValue) }},
		{"sessionDuration", func(d *dto) { d.SessionDuration = ptr.To("120") }},
		{"homePageUrl", func(d *dto) { d.HomePageURL = ptr.To("/home") }},
		{"disableAnimations", func(d *dto) { d.DisableAnimations = ptr.To(testTrueStr) }},
		{"allowOwnAccountEdit", func(d *dto) { d.AllowOwnAccountEdit = ptr.To(testFalseStr) }},
		{"allowUserSignups", func(d *dto) { d.AllowUserSignups = ptr.To("open") }},
		{"emailsVerified", func(d *dto) { d.EmailsVerified = ptr.To(testTrueStr) }},
		{"smtpTls", func(d *dto) { d.SMTPTLS = ptr.To("tls") }},
		{"emailLoginNotificationEnabled", func(d *dto) { d.EmailLoginNotificationEnabled = ptr.To(testTrueStr) }},
		{"emailOneTimeAccessAsAdminEnabled", func(d *dto) { d.EmailOneTimeAccessAsAdminEnabled = ptr.To(testTrueStr) }},
		{"emailApiKeyExpirationEnabled", func(d *dto) { d.EmailAPIKeyExpirationEnabled = ptr.To(testTrueStr) }},
		{"emailOneTimeAccessAsUnauthenticatedEnabled", func(d *dto) {
			d.EmailOneTimeAccessAsUnauthenticatedEnabled = ptr.To(testTrueStr)
		}},
		{"emailVerificationEnabled", func(d *dto) { d.EmailVerificationEnabled = ptr.To(testTrueStr) }},
		{"ldapEnabled", func(d *dto) { d.LdapEnabled = ptr.To(testTrueStr) }},
		{"requireUserEmail", func(d *dto) { d.RequireUserEmail = ptr.To(testFalseStr) }},
	}

	for _, tc := range ptrFields {
		t.Run(tc.key, func(t *testing.T) {
			current := pocketid.AppConfig{tc.key: "old"}
			d := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
			tc.setField(d)

			if !appConfigNeedsUpdate(current, d) {
				t.Errorf("expected update needed when ptr field %s changed", tc.key)
			}
		})
	}
}

func TestAppConfigNeedsUpdate_EveryStrField(t *testing.T) {
	type dto = models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto
	strFields := []struct {
		key      string
		setField func(*dto)
	}{
		{"accentColor", func(d *dto) { d.AccentColor = testNewValue }},
		{"signupDefaultCustomClaims", func(d *dto) { d.SignupDefaultCustomClaims = testNewValue }},
		{"signupDefaultUserGroupIDs", func(d *dto) { d.SignupDefaultUserGroupIDs = testNewValue }},
		{"smtpHost", func(d *dto) { d.SMTPHost = testNewValue }},
		{"smtpPort", func(d *dto) { d.SMTPPort = "587" }},
		{"smtpFrom", func(d *dto) { d.SMTPFrom = "new@example.com" }},
		{"smtpUser", func(d *dto) { d.SMTPUser = testNewValue }},
		{"smtpPassword", func(d *dto) { d.SMTPPassword = testNewValue }},
		{"smtpSkipCertVerify", func(d *dto) { d.SMTPSkipCertVerify = testTrueStr }},
		{"ldapUrl", func(d *dto) { d.LdapURL = testNewValue }},
		{"ldapBindDn", func(d *dto) { d.LdapBindDn = testNewValue }},
		{"ldapBindPassword", func(d *dto) { d.LdapBindPassword = testNewValue }},
		{"ldapBase", func(d *dto) { d.LdapBase = testNewValue }},
		{"ldapSkipCertVerify", func(d *dto) { d.LdapSkipCertVerify = testTrueStr }},
		{"ldapSoftDeleteUsers", func(d *dto) { d.LdapSoftDeleteUsers = testTrueStr }},
		{"ldapAdminGroupName", func(d *dto) { d.LdapAdminGroupName = testNewValue }},
		{"ldapUserSearchFilter", func(d *dto) { d.LdapUserSearchFilter = testNewValue }},
		{"ldapUserGroupSearchFilter", func(d *dto) { d.LdapUserGroupSearchFilter = testNewValue }},
		{"ldapAttributeUserUniqueIdentifier", func(d *dto) { d.LdapAttributeUserUniqueIdentifier = testNewValue }},
		{"ldapAttributeUserUsername", func(d *dto) { d.LdapAttributeUserUsername = testNewValue }},
		{"ldapAttributeUserEmail", func(d *dto) { d.LdapAttributeUserEmail = testNewValue }},
		{"ldapAttributeUserFirstName", func(d *dto) { d.LdapAttributeUserFirstName = testNewValue }},
		{"ldapAttributeUserLastName", func(d *dto) { d.LdapAttributeUserLastName = testNewValue }},
		{"ldapAttributeUserDisplayName", func(d *dto) { d.LdapAttributeUserDisplayName = testNewValue }},
		{"ldapAttributeUserProfilePicture", func(d *dto) { d.LdapAttributeUserProfilePicture = testNewValue }},
		{"ldapAttributeGroupMember", func(d *dto) { d.LdapAttributeGroupMember = testNewValue }},
		{"ldapAttributeGroupUniqueIdentifier", func(d *dto) { d.LdapAttributeGroupUniqueIdentifier = testNewValue }},
		{"ldapAttributeGroupName", func(d *dto) { d.LdapAttributeGroupName = testNewValue }},
	}

	for _, tc := range strFields {
		t.Run(tc.key, func(t *testing.T) {
			current := pocketid.AppConfig{tc.key: "old"}
			dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
			tc.setField(dto)

			if !appConfigNeedsUpdate(current, dto) {
				t.Errorf("expected update needed when str field %s changed", tc.key)
			}
		})
	}
}

func TestAppConfigNeedsUpdate_MatchingPtrFieldNoUpdate(t *testing.T) {
	current := pocketid.AppConfig{
		"appName":                                    "Test",
		"sessionDuration":                            "60",
		"homePageUrl":                                "/home",
		"disableAnimations":                          "false",
		"allowOwnAccountEdit":                        "true",
		"allowUserSignups":                           "disabled",
		"emailsVerified":                             "false",
		"smtpTls":                                    "none",
		"emailLoginNotificationEnabled":              "true",
		"emailOneTimeAccessAsAdminEnabled":           "false",
		"emailApiKeyExpirationEnabled":               "true",
		"emailOneTimeAccessAsUnauthenticatedEnabled": "false",
		"emailVerificationEnabled":                   "true",
		"ldapEnabled":                                "false",
		"requireUserEmail":                           "true",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AppName:                          ptr.To("Test"),
		SessionDuration:                  ptr.To("60"),
		HomePageURL:                      ptr.To("/home"),
		DisableAnimations:                ptr.To("false"),
		AllowOwnAccountEdit:              ptr.To("true"),
		AllowUserSignups:                 ptr.To("disabled"),
		EmailsVerified:                   ptr.To("false"),
		SMTPTLS:                          ptr.To("none"),
		EmailLoginNotificationEnabled:    ptr.To("true"),
		EmailOneTimeAccessAsAdminEnabled: ptr.To("false"),
		EmailAPIKeyExpirationEnabled:     ptr.To("true"),
		EmailOneTimeAccessAsUnauthenticatedEnabled: ptr.To("false"),
		EmailVerificationEnabled:                   ptr.To("true"),
		LdapEnabled:                                ptr.To("false"),
		RequireUserEmail:                           ptr.To("true"),
	}

	if appConfigNeedsUpdate(current, dto) {
		t.Error("expected no update when all ptr fields match")
	}
}

func TestAppConfigNeedsUpdate_MatchingStrFieldNoUpdate(t *testing.T) {
	current := pocketid.AppConfig{
		"accentColor":                       "#ff0000",
		"smtpHost":                          "smtp.example.com",
		"smtpPort":                          "587",
		"smtpFrom":                          "noreply@example.com",
		"ldapUrl":                           "ldaps://ldap.example.com",
		"ldapBindDn":                        "cn=admin,dc=example,dc=com",
		"ldapBase":                          "dc=example,dc=com",
		"ldapAttributeUserUniqueIdentifier": "entryUUID",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AccentColor:                       "#ff0000",
		SMTPHost:                          "smtp.example.com",
		SMTPPort:                          "587",
		SMTPFrom:                          "noreply@example.com",
		LdapURL:                           "ldaps://ldap.example.com",
		LdapBindDn:                        "cn=admin,dc=example,dc=com",
		LdapBase:                          "dc=example,dc=com",
		LdapAttributeUserUniqueIdentifier: "entryUUID",
	}

	if appConfigNeedsUpdate(current, dto) {
		t.Error("expected no update when all str fields match")
	}
}

// --- applyUIConfig tests ---

func TestApplyUIConfig_NilUI(t *testing.T) {
	inst := minimalInstance()
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AppName: ptr.To("Original"),
	}

	r := &Reconciler{}
	r.applyUIConfig(inst, dto)

	if *dto.AppName != "Original" {
		t.Error("nil UI should not modify dto")
	}
}

func TestApplyUIConfig_AllFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.UI = &pocketidinternalv1alpha1.UIConfig{
		AppName:           "My App",
		SessionDuration:   ptr.To(int32(120)),
		HomePageURL:       "/dashboard",
		DisableAnimations: ptr.To(true),
		AccentColor:       "#00ff00",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	r.applyUIConfig(inst, dto)

	if *dto.AppName != "My App" {
		t.Errorf("AppName = %q, want %q", *dto.AppName, "My App")
	}
	if *dto.SessionDuration != "120" {
		t.Errorf("SessionDuration = %q, want %q", *dto.SessionDuration, "120")
	}
	if *dto.HomePageURL != "/dashboard" {
		t.Errorf("HomePageURL = %q, want %q", *dto.HomePageURL, "/dashboard")
	}
	if *dto.DisableAnimations != testTrueStr {
		t.Errorf("DisableAnimations = %q, want %q", *dto.DisableAnimations, testTrueStr)
	}
	if dto.AccentColor != "#00ff00" {
		t.Errorf("AccentColor = %q, want %q", dto.AccentColor, "#00ff00")
	}
}

func TestApplyUIConfig_PartialFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.UI = &pocketidinternalv1alpha1.UIConfig{
		AppName: "Only Name",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		SessionDuration: ptr.To("60"),
		AccentColor:     "#ff0000",
	}

	r := &Reconciler{}
	r.applyUIConfig(inst, dto)

	if *dto.AppName != "Only Name" {
		t.Errorf("AppName = %q, want %q", *dto.AppName, "Only Name")
	}
	// Existing values should be preserved
	if *dto.SessionDuration != "60" {
		t.Errorf("SessionDuration should be preserved, got %q", *dto.SessionDuration)
	}
	if dto.AccentColor != "#ff0000" {
		t.Errorf("AccentColor should be preserved, got %q", dto.AccentColor)
	}
}

// --- applyUserManagementConfig tests ---

func TestApplyUserManagementConfig_NilUM(t *testing.T) {
	inst := minimalInstance()
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AllowUserSignups: ptr.To("disabled"),
	}

	r := &Reconciler{}
	r.applyUserManagementConfig(inst, dto)

	if *dto.AllowUserSignups != "disabled" {
		t.Error("nil UserManagement should not modify dto")
	}
}

func TestApplyUserManagementConfig_AllFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.UserManagement = &pocketidinternalv1alpha1.UserManagementConfig{
		RequireUserEmail:          ptr.To(false),
		EmailsVerified:            ptr.To(true),
		AllowOwnAccountEdit:       ptr.To(false),
		AllowUserSignups:          "open",
		SignupDefaultCustomClaims: `[{"key":"role","value":"user"}]`,
		SignupDefaultUserGroupIDs: []string{"group-1", "group-2"},
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	r.applyUserManagementConfig(inst, dto)

	if *dto.RequireUserEmail != testFalseStr {
		t.Errorf("RequireUserEmail = %q, want %q", *dto.RequireUserEmail, testFalseStr)
	}
	if *dto.EmailsVerified != testTrueStr {
		t.Errorf("EmailsVerified = %q, want %q", *dto.EmailsVerified, testTrueStr)
	}
	if *dto.AllowOwnAccountEdit != testFalseStr {
		t.Errorf("AllowOwnAccountEdit = %q, want %q", *dto.AllowOwnAccountEdit, testFalseStr)
	}
	if *dto.AllowUserSignups != "open" {
		t.Errorf("AllowUserSignups = %q, want %q", *dto.AllowUserSignups, "open")
	}
	if dto.SignupDefaultCustomClaims != `[{"key":"role","value":"user"}]` {
		t.Errorf("SignupDefaultCustomClaims = %q, want JSON array", dto.SignupDefaultCustomClaims)
	}
	if dto.SignupDefaultUserGroupIDs != "group-1,group-2" {
		t.Errorf("SignupDefaultUserGroupIDs = %q, want %q", dto.SignupDefaultUserGroupIDs, "group-1,group-2")
	}
}

// --- applyEmailNotificationsConfig tests ---

func TestApplyEmailNotificationsConfig_NilEN(t *testing.T) {
	inst := minimalInstance()
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		EmailLoginNotificationEnabled: ptr.To(testTrueStr),
	}

	r := &Reconciler{}
	r.applyEmailNotificationsConfig(inst, dto)

	if *dto.EmailLoginNotificationEnabled != testTrueStr {
		t.Error("nil EmailNotifications should not modify dto")
	}
}

func TestApplyEmailNotificationsConfig_AllFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{
		LoginNotification:              ptr.To(true),
		OneTimeAccessAsAdmin:           ptr.To(false),
		APIKeyExpiration:               ptr.To(true),
		OneTimeAccessAsUnauthenticated: ptr.To(false),
		Verification:                   ptr.To(true),
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	r.applyEmailNotificationsConfig(inst, dto)

	checks := []struct {
		name string
		got  *string
		want string
	}{
		{"EmailLoginNotificationEnabled", dto.EmailLoginNotificationEnabled, testTrueStr},
		{"EmailOneTimeAccessAsAdminEnabled", dto.EmailOneTimeAccessAsAdminEnabled, testFalseStr},
		{"EmailAPIKeyExpirationEnabled", dto.EmailAPIKeyExpirationEnabled, testTrueStr},
		{"EmailOneTimeAccessAsUnauthenticatedEnabled", dto.EmailOneTimeAccessAsUnauthenticatedEnabled, testFalseStr},
		{"EmailVerificationEnabled", dto.EmailVerificationEnabled, testTrueStr},
	}

	for _, c := range checks {
		if c.got == nil {
			t.Errorf("%s should be set, got nil", c.name)
		} else if *c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, *c.got, c.want)
		}
	}
}

func TestApplyEmailNotificationsConfig_PartialFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{
		LoginNotification: ptr.To(false),
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		EmailAPIKeyExpirationEnabled: ptr.To(testTrueStr),
	}

	r := &Reconciler{}
	r.applyEmailNotificationsConfig(inst, dto)

	if *dto.EmailLoginNotificationEnabled != testFalseStr {
		t.Errorf("EmailLoginNotificationEnabled = %q, want %q", *dto.EmailLoginNotificationEnabled, testFalseStr)
	}
	// Existing value should be preserved
	if *dto.EmailAPIKeyExpirationEnabled != testTrueStr {
		t.Errorf("EmailAPIKeyExpirationEnabled should be preserved, got %q", *dto.EmailAPIKeyExpirationEnabled)
	}
}

// --- applyLDAPConfig tests ---

func TestApplyLDAPConfig_NilLDAP(t *testing.T) {
	inst := minimalInstance()
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		LdapEnabled: ptr.To(testFalseStr),
	}

	r := &Reconciler{}
	err := r.applyLDAPConfig(context.TODO(), inst, dto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *dto.LdapEnabled != testFalseStr {
		t.Error("nil LDAP should not modify dto")
	}
}

func TestApplyLDAPConfig_SetsEnabledAndRequiredFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.LDAP = &pocketidinternalv1alpha1.LDAPConfig{
		URL:          "ldaps://ldap.example.com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: pocketidinternalv1alpha1.SensitiveValue{Value: "secret"},
		Base:         "dc=example,dc=com",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	err := r.applyLDAPConfig(context.TODO(), inst, dto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *dto.LdapEnabled != testTrueStr {
		t.Error("LDAP should be enabled when config is set")
	}
	if dto.LdapURL != "ldaps://ldap.example.com" {
		t.Errorf("LdapURL = %q, want ldaps://ldap.example.com", dto.LdapURL)
	}
	if dto.LdapBindDn != "cn=admin,dc=example,dc=com" {
		t.Errorf("LdapBindDn = %q", dto.LdapBindDn)
	}
	if dto.LdapBindPassword != "secret" {
		t.Errorf("LdapBindPassword = %q, want secret", dto.LdapBindPassword)
	}
	if dto.LdapBase != "dc=example,dc=com" {
		t.Errorf("LdapBase = %q", dto.LdapBase)
	}
}

func TestApplyLDAPConfig_OptionalFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.LDAP = &pocketidinternalv1alpha1.LDAPConfig{
		URL:                   "ldaps://ldap.example.com",
		BindDN:                "cn=admin,dc=example,dc=com",
		BindPassword:          pocketidinternalv1alpha1.SensitiveValue{Value: "secret"},
		Base:                  "dc=example,dc=com",
		SkipCertVerify:        ptr.To(true),
		SoftDeleteUsers:       ptr.To(true),
		AdminGroupName:        "admins",
		UserSearchFilter:      "(objectClass=person)",
		UserGroupSearchFilter: "(objectClass=group)",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	err := r.applyLDAPConfig(context.TODO(), inst, dto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dto.LdapSkipCertVerify != testTrueStr {
		t.Errorf("LdapSkipCertVerify = %q, want true", dto.LdapSkipCertVerify)
	}
	if dto.LdapSoftDeleteUsers != testTrueStr {
		t.Errorf("LdapSoftDeleteUsers = %q, want true", dto.LdapSoftDeleteUsers)
	}
	if dto.LdapAdminGroupName != "admins" {
		t.Errorf("LdapAdminGroupName = %q, want admins", dto.LdapAdminGroupName)
	}
	if dto.LdapUserSearchFilter != "(objectClass=person)" {
		t.Errorf("LdapUserSearchFilter = %q", dto.LdapUserSearchFilter)
	}
	if dto.LdapUserGroupSearchFilter != "(objectClass=group)" {
		t.Errorf("LdapUserGroupSearchFilter = %q", dto.LdapUserGroupSearchFilter)
	}
}

func TestApplyLDAPConfig_AttributeMapping(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.LDAP = &pocketidinternalv1alpha1.LDAPConfig{
		URL:          "ldaps://ldap.example.com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: pocketidinternalv1alpha1.SensitiveValue{Value: "secret"},
		Base:         "dc=example,dc=com",
		AttributeMapping: &pocketidinternalv1alpha1.LDAPAttributeMappingConfig{
			UserUniqueIdentifier:  "entryUUID",
			UserUsername:          "uid",
			UserEmail:             "mail",
			UserFirstName:         "givenName",
			UserLastName:          "sn",
			UserDisplayName:       "displayName",
			UserProfilePicture:    "jpegPhoto",
			GroupMember:           "member",
			GroupUniqueIdentifier: "entryUUID",
			GroupName:             "cn",
		},
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	err := r.applyLDAPConfig(context.TODO(), inst, dto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"UserUniqueIdentifier", dto.LdapAttributeUserUniqueIdentifier, "entryUUID"},
		{"UserUsername", dto.LdapAttributeUserUsername, "uid"},
		{"UserEmail", dto.LdapAttributeUserEmail, "mail"},
		{"UserFirstName", dto.LdapAttributeUserFirstName, "givenName"},
		{"UserLastName", dto.LdapAttributeUserLastName, "sn"},
		{"UserDisplayName", dto.LdapAttributeUserDisplayName, "displayName"},
		{"UserProfilePicture", dto.LdapAttributeUserProfilePicture, "jpegPhoto"},
		{"GroupMember", dto.LdapAttributeGroupMember, "member"},
		{"GroupUniqueIdentifier", dto.LdapAttributeGroupUniqueIdentifier, "entryUUID"},
		{"GroupName", dto.LdapAttributeGroupName, "cn"},
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("LdapAttribute%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// --- applySMTPConfig tests ---

func TestApplySMTPConfig_NilSMTP(t *testing.T) {
	inst := minimalInstance()
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		SMTPHost: "original.example.com",
	}

	r := &Reconciler{}
	err := r.applySMTPConfig(context.TODO(), inst, dto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dto.SMTPHost != "original.example.com" {
		t.Error("nil SMTP should not modify dto")
	}
}

func TestApplySMTPConfig_RequiredFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.SMTP = &pocketidinternalv1alpha1.SMTPConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	err := r.applySMTPConfig(context.TODO(), inst, dto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dto.SMTPHost != "smtp.example.com" {
		t.Errorf("SMTPHost = %q", dto.SMTPHost)
	}
	if dto.SMTPPort != "587" {
		t.Errorf("SMTPPort = %q, want 587", dto.SMTPPort)
	}
	if dto.SMTPFrom != "noreply@example.com" {
		t.Errorf("SMTPFrom = %q", dto.SMTPFrom)
	}
}

func TestApplySMTPConfig_OptionalFields(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.SMTP = &pocketidinternalv1alpha1.SMTPConfig{
		Host:           "smtp.example.com",
		Port:           465,
		From:           "noreply@example.com",
		User:           "smtp-user",
		Password:       &pocketidinternalv1alpha1.SensitiveValue{Value: "smtp-pass"},
		TLS:            "tls",
		SkipCertVerify: ptr.To(true),
	}

	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{}
	r := &Reconciler{}
	err := r.applySMTPConfig(context.TODO(), inst, dto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dto.SMTPUser != "smtp-user" {
		t.Errorf("SMTPUser = %q", dto.SMTPUser)
	}
	if dto.SMTPPassword != "smtp-pass" {
		t.Errorf("SMTPPassword = %q", dto.SMTPPassword)
	}
	if *dto.SMTPTLS != "tls" {
		t.Errorf("SMTPTLS = %q, want tls", *dto.SMTPTLS)
	}
	if dto.SMTPSkipCertVerify != testTrueStr {
		t.Errorf("SMTPSkipCertVerify = %q, want true", dto.SMTPSkipCertVerify)
	}
}

// --- buildDesiredAppConfig integration-style test ---

func TestBuildDesiredAppConfig_PreservesUnmanagedFields(t *testing.T) {
	current := pocketid.AppConfig{
		"appName":         "Pocket ID",
		"sessionDuration": "60",
		"homePageUrl":     "/old",
		"smtpHost":        "old-smtp.example.com",
		"smtpPort":        "25",
		"smtpFrom":        "old@example.com",
		"ldapEnabled":     "false",
		"accentColor":     "#aabbcc",
	}

	inst := minimalInstance()
	inst.Spec.UI = &pocketidinternalv1alpha1.UIConfig{
		AppName: "New Name",
	}

	r := &Reconciler{}
	dto, err := r.buildDesiredAppConfig(context.TODO(), inst, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Managed field should be overridden
	if *dto.AppName != "New Name" {
		t.Errorf("AppName = %q, want New Name", *dto.AppName)
	}

	// Unmanaged fields should be preserved from current
	if *dto.SessionDuration != "60" {
		t.Errorf("SessionDuration = %q, want 60 (preserved)", *dto.SessionDuration)
	}
	if dto.SMTPHost != "old-smtp.example.com" {
		t.Errorf("SMTPHost = %q, want old-smtp.example.com (preserved)", dto.SMTPHost)
	}
	if dto.AccentColor != "#aabbcc" {
		t.Errorf("AccentColor = %q, want #aabbcc (preserved)", dto.AccentColor)
	}
}

func TestBuildDesiredAppConfig_MultipleOverlays(t *testing.T) {
	current := pocketid.AppConfig{
		"appName":                       "Pocket ID",
		"emailLoginNotificationEnabled": "false",
		"smtpHost":                      "",
		"smtpPort":                      "",
		"smtpFrom":                      "",
	}

	inst := minimalInstance()
	inst.Spec.UI = &pocketidinternalv1alpha1.UIConfig{
		AppName:     "My SSO",
		AccentColor: "#00ff00",
	}
	inst.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{
		LoginNotification: ptr.To(true),
	}
	inst.Spec.SMTP = &pocketidinternalv1alpha1.SMTPConfig{
		Host: "smtp.new.com",
		Port: 587,
		From: "noreply@new.com",
	}

	r := &Reconciler{}
	dto, err := r.buildDesiredAppConfig(context.TODO(), inst, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *dto.AppName != "My SSO" {
		t.Errorf("AppName = %q, want My SSO", *dto.AppName)
	}
	if dto.AccentColor != "#00ff00" {
		t.Errorf("AccentColor = %q, want #00ff00", dto.AccentColor)
	}
	if *dto.EmailLoginNotificationEnabled != "true" {
		t.Errorf("EmailLoginNotificationEnabled = %q, want true", *dto.EmailLoginNotificationEnabled)
	}
	if dto.SMTPHost != "smtp.new.com" {
		t.Errorf("SMTPHost = %q, want smtp.new.com", dto.SMTPHost)
	}
	if dto.SMTPPort != fmt.Sprintf("%d", 587) {
		t.Errorf("SMTPPort = %q, want 587", dto.SMTPPort)
	}
}
