package instance

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// helper to find an env var by name in a slice
func findEnv(envs []corev1.EnvVar, name string) *corev1.EnvVar {
	for i := range envs {
		if envs[i].Name == name {
			return &envs[i]
		}
	}
	return nil
}

func requireEnv(t *testing.T, envs []corev1.EnvVar, name, expectedValue string) {
	t.Helper()
	e := findEnv(envs, name)
	if e == nil {
		t.Errorf("expected env var %s to be set", name)
		return
	}
	if e.Value != expectedValue {
		t.Errorf("env %s: got %q, want %q", name, e.Value, expectedValue)
	}
}

func requireEnvFromSecret(t *testing.T, envs []corev1.EnvVar, name, secretName, secretKey string) {
	t.Helper()
	e := findEnv(envs, name)
	if e == nil {
		t.Errorf("expected env var %s to be set", name)
		return
	}
	if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
		t.Errorf("env %s: expected secretKeyRef, got value=%q", name, e.Value)
		return
	}
	if e.ValueFrom.SecretKeyRef.Name != secretName {
		t.Errorf("env %s secretKeyRef.Name: got %q, want %q", name, e.ValueFrom.SecretKeyRef.Name, secretName)
	}
	if e.ValueFrom.SecretKeyRef.Key != secretKey {
		t.Errorf("env %s secretKeyRef.Key: got %q, want %q", name, e.ValueFrom.SecretKeyRef.Key, secretKey)
	}
}

func requireEnvAbsent(t *testing.T, envs []corev1.EnvVar, name string) {
	t.Helper()
	if findEnv(envs, name) != nil {
		t.Errorf("expected env var %s to be absent", name)
	}
}

func minimalInstance() *pocketidinternalv1alpha1.PocketIDInstance {
	inst := &pocketidinternalv1alpha1.PocketIDInstance{}
	inst.Name = "test-instance"
	inst.Namespace = "default"
	inst.Spec.EncryptionKey = pocketidinternalv1alpha1.EnvValue{Value: "test-encryption-key-32chars!!!!!"}
	return inst
}

func TestBuildEnvVars_CoreAlwaysSet(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.AppURL = "https://id.example.com"

	env := buildEnvVars(inst)

	requireEnv(t, env, "ENCRYPTION_KEY", "test-encryption-key-32chars!!!!!")
	requireEnv(t, env, "TRUST_PROXY", "true")
	requireEnv(t, env, "DISABLE_RATE_LIMITING", "true")
	requireEnv(t, env, "APP_URL", "https://id.example.com")
	requireEnvFromSecret(t, env, "STATIC_API_KEY", "test-instance-static-api-key", "token")
}

func TestBuildEnvVars_UIConfigDisabledAbsentByDefault(t *testing.T) {
	inst := minimalInstance()
	env := buildEnvVars(inst)
	requireEnvAbsent(t, env, "UI_CONFIG_DISABLED")
}

func TestBuildEnvVars_UIConfigDisabledWhenUISet(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.UI = &pocketidinternalv1alpha1.UIConfig{AppName: "Test"}
	requireEnv(t, buildEnvVars(inst), "UI_CONFIG_DISABLED", "true")
}

func TestBuildEnvVars_UIConfigDisabledWhenUserManagementSet(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.UserManagement = &pocketidinternalv1alpha1.UserManagementConfig{EmailsVerified: true}
	requireEnv(t, buildEnvVars(inst), "UI_CONFIG_DISABLED", "true")
}

func TestBuildEnvVars_UIConfigDisabledWhenSMTPSet(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.SMTP = &pocketidinternalv1alpha1.SMTPConfig{
		Host: "smtp.example.com",
		Port: 25,
		From: "noreply@example.com",
	}
	requireEnv(t, buildEnvVars(inst), "UI_CONFIG_DISABLED", "true")
}

func TestBuildEnvVars_UIConfigDisabledWhenEmailNotificationsSet(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{}
	requireEnv(t, buildEnvVars(inst), "UI_CONFIG_DISABLED", "true")
}

func TestBuildEnvVars_UIConfigDisabledWhenLDAPSet(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.LDAP = &pocketidinternalv1alpha1.LDAPConfig{
		URL:          "ldaps://ldap.example.com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: pocketidinternalv1alpha1.SensitiveValue{Value: "secret"},
		Base:         "dc=example,dc=com",
	}
	requireEnv(t, buildEnvVars(inst), "UI_CONFIG_DISABLED", "true")
}

func TestBuildEnvVars_DatabaseUrl(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.DatabaseUrl = &pocketidinternalv1alpha1.EnvValue{Value: "postgres://localhost/pocket-id"}

	env := buildEnvVars(inst)
	requireEnv(t, env, "DB_CONNECTION_STRING", "postgres://localhost/pocket-id")
}

func TestBuildEnvVars_DatabaseUrlFromSecret(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.DatabaseUrl = &pocketidinternalv1alpha1.EnvValue{
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "db-secret"},
				Key:                  "uri",
			},
		},
	}

	env := buildEnvVars(inst)
	requireEnvFromSecret(t, env, "DB_CONNECTION_STRING", "db-secret", "uri")
}

func TestBuildEnvVars_FileBackendFilesystem(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.FileBackend = "filesystem"

	env := buildEnvVars(inst)
	requireEnv(t, env, "FILE_BACKEND", "filesystem")
}

func TestBuildEnvVars_FileBackendDatabase(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.FileBackend = "database"

	env := buildEnvVars(inst)
	requireEnv(t, env, "FILE_BACKEND", "database")
}

func TestBuildEnvVars_FileBackendIgnoredWhenS3Present(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.FileBackend = "s3"
	inst.Spec.S3 = &pocketidinternalv1alpha1.S3Config{
		Bucket:          "my-bucket",
		Region:          "us-east-1",
		AccessKeyID:     pocketidinternalv1alpha1.SensitiveValue{Value: "key"},
		SecretAccessKey: pocketidinternalv1alpha1.SensitiveValue{Value: "secret"},
	}

	env := buildEnvVars(inst)
	// FILE_BACKEND should be set by S3 builder, not the fileBackend builder
	requireEnv(t, env, "FILE_BACKEND", "s3")

	// Verify FILE_BACKEND appears exactly once
	count := 0
	for _, e := range env {
		if e.Name == "FILE_BACKEND" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected FILE_BACKEND to appear once, got %d", count)
	}
}

func TestBuildEnvVars_FileBackendAbsentByDefault(t *testing.T) {
	inst := minimalInstance()
	env := buildEnvVars(inst)
	requireEnvAbsent(t, env, "FILE_BACKEND")
}

func TestBuildEnvVars_S3(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.S3 = &pocketidinternalv1alpha1.S3Config{
		Bucket:   "my-bucket",
		Region:   "us-east-1",
		Endpoint: "https://minio.example.com",
		AccessKeyID: pocketidinternalv1alpha1.SensitiveValue{
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "s3-creds"},
					Key:                  "access-key",
				},
			},
		},
		SecretAccessKey: pocketidinternalv1alpha1.SensitiveValue{Value: "my-secret-key"},
		ForcePathStyle:  true,
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "FILE_BACKEND", "s3")
	requireEnv(t, env, "S3_BUCKET", "my-bucket")
	requireEnv(t, env, "S3_REGION", "us-east-1")
	requireEnv(t, env, "S3_ENDPOINT", "https://minio.example.com")
	requireEnvFromSecret(t, env, "S3_ACCESS_KEY_ID", "s3-creds", "access-key")
	requireEnv(t, env, "S3_SECRET_ACCESS_KEY", "my-secret-key")
	requireEnv(t, env, "S3_FORCE_PATH_STYLE", "true")
	requireEnvAbsent(t, env, "S3_DISABLE_DEFAULT_INTEGRITY_CHECKS")
}

func TestBuildEnvVars_S3DisableIntegrityChecks(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.S3 = &pocketidinternalv1alpha1.S3Config{
		Bucket:                        "my-bucket",
		Region:                        "us-east-1",
		AccessKeyID:                   pocketidinternalv1alpha1.SensitiveValue{Value: "key"},
		SecretAccessKey:               pocketidinternalv1alpha1.SensitiveValue{Value: "secret"},
		DisableDefaultIntegrityChecks: true,
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "S3_DISABLE_DEFAULT_INTEGRITY_CHECKS", "true")
}

func TestBuildEnvVars_S3Absent(t *testing.T) {
	inst := minimalInstance()
	env := buildEnvVars(inst)
	requireEnvAbsent(t, env, "FILE_BACKEND")
	requireEnvAbsent(t, env, "S3_BUCKET")
}

func TestBuildEnvVars_SMTP(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.SMTP = &pocketidinternalv1alpha1.SMTPConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
		User: "smtpuser",
		Password: &pocketidinternalv1alpha1.SensitiveValue{
			Value: "smtp-pass",
		},
		TLS:            "starttls",
		SkipCertVerify: true,
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "SMTP_ENABLED", "true")
	requireEnv(t, env, "SMTP_HOST", "smtp.example.com")
	requireEnv(t, env, "SMTP_PORT", "587")
	requireEnv(t, env, "SMTP_FROM", "noreply@example.com")
	requireEnv(t, env, "SMTP_USER", "smtpuser")
	requireEnv(t, env, "SMTP_PASSWORD", "smtp-pass")
	requireEnv(t, env, "SMTP_TLS", "starttls")
	requireEnv(t, env, "SMTP_SKIP_CERT_VERIFY", "true")
}

func TestBuildEnvVars_SMTPMinimal(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.SMTP = &pocketidinternalv1alpha1.SMTPConfig{
		Host: "smtp.example.com",
		Port: 25,
		From: "noreply@example.com",
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "SMTP_ENABLED", "true")
	requireEnvAbsent(t, env, "SMTP_USER")
	requireEnvAbsent(t, env, "SMTP_PASSWORD")
	requireEnvAbsent(t, env, "SMTP_SKIP_CERT_VERIFY")
}

func TestBuildEnvVars_EmailNotifications(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{
		LoginNotification:              true,
		OneTimeAccessAsAdmin:           true,
		APIKeyExpiration:               true,
		OneTimeAccessAsUnauthenticated: true,
		Verification:                   true,
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "EMAIL_LOGIN_NOTIFICATION_ENABLED", "true")
	requireEnv(t, env, "EMAIL_ONE_TIME_ACCESS_AS_ADMIN_ENABLED", "true")
	requireEnv(t, env, "EMAIL_API_KEY_EXPIRATION_ENABLED", "true")
	requireEnv(t, env, "EMAIL_ONE_TIME_ACCESS_AS_UNAUTHENTICATED_ENABLED", "true")
	requireEnv(t, env, "EMAIL_VERIFICATION_ENABLED", "true")
}

func TestBuildEnvVars_EmailNotificationsAllFalse(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.EmailNotifications = &pocketidinternalv1alpha1.EmailNotificationsConfig{}

	env := buildEnvVars(inst)
	requireEnvAbsent(t, env, "EMAIL_LOGIN_NOTIFICATION_ENABLED")
	requireEnvAbsent(t, env, "EMAIL_ONE_TIME_ACCESS_AS_ADMIN_ENABLED")
}

func TestBuildEnvVars_LDAP(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.LDAP = &pocketidinternalv1alpha1.LDAPConfig{
		URL:    "ldaps://ldap.example.com",
		BindDN: "cn=admin,dc=example,dc=com",
		BindPassword: pocketidinternalv1alpha1.SensitiveValue{
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "ldap-creds"},
					Key:                  "password",
				},
			},
		},
		Base:                  "dc=example,dc=com",
		SkipCertVerify:        true,
		SoftDeleteUsers:       true,
		AdminGroupName:        "admins",
		UserSearchFilter:      "(objectClass=inetOrgPerson)",
		UserGroupSearchFilter: "(objectClass=groupOfNames)",
		AttributeMapping: &pocketidinternalv1alpha1.LDAPAttributeMappingConfig{
			UserUniqueIdentifier: "entryUUID",
			UserUsername:         "uid",
			UserEmail:            "mail",
			UserFirstName:        "givenName",
			UserLastName:         "sn",
			GroupMember:          "member",
			GroupName:            "cn",
		},
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "LDAP_ENABLED", "true")
	requireEnv(t, env, "LDAP_URL", "ldaps://ldap.example.com")
	requireEnv(t, env, "LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
	requireEnvFromSecret(t, env, "LDAP_BIND_PASSWORD", "ldap-creds", "password")
	requireEnv(t, env, "LDAP_BASE", "dc=example,dc=com")
	requireEnv(t, env, "LDAP_SKIP_CERT_VERIFY", "true")
	requireEnv(t, env, "LDAP_SOFT_DELETE_USERS", "true")
	requireEnv(t, env, "LDAP_ADMIN_GROUP_NAME", "admins")
	requireEnv(t, env, "LDAP_USER_SEARCH_FILTER", "(objectClass=inetOrgPerson)")
	requireEnv(t, env, "LDAP_USER_GROUP_SEARCH_FILTER", "(objectClass=groupOfNames)")
	requireEnv(t, env, "LDAP_ATTRIBUTE_USER_UNIQUE_IDENTIFIER", "entryUUID")
	requireEnv(t, env, "LDAP_ATTRIBUTE_USER_USERNAME", "uid")
	requireEnv(t, env, "LDAP_ATTRIBUTE_USER_EMAIL", "mail")
	requireEnv(t, env, "LDAP_ATTRIBUTE_USER_FIRST_NAME", "givenName")
	requireEnv(t, env, "LDAP_ATTRIBUTE_USER_LAST_NAME", "sn")
	requireEnv(t, env, "LDAP_ATTRIBUTE_GROUP_MEMBER", "member")
	requireEnv(t, env, "LDAP_ATTRIBUTE_GROUP_NAME", "cn")
}

func TestBuildEnvVars_Logging(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Logging = &pocketidinternalv1alpha1.LoggingConfig{
		Level: "debug",
		JSON:  true,
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "LOG_LEVEL", "debug")
	requireEnv(t, env, "LOG_JSON", "true")
}

func TestBuildEnvVars_Tracing(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Tracing = &pocketidinternalv1alpha1.TracingConfig{}

	env := buildEnvVars(inst)
	requireEnv(t, env, "TRACING_ENABLED", "true")
}

func TestBuildEnvVars_TracingAbsent(t *testing.T) {
	inst := minimalInstance()
	env := buildEnvVars(inst)
	requireEnvAbsent(t, env, "TRACING_ENABLED")
}

func TestBuildEnvVars_Metrics(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Metrics = &pocketidinternalv1alpha1.MetricsConfig{
		Enabled: true,
		Port:    9999,
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "METRICS_ENABLED", "true")
	requireEnv(t, env, "OTEL_METRICS_EXPORTER", "prometheus")
	requireEnv(t, env, "OTEL_EXPORTER_PROMETHEUS_HOST", "0.0.0.0")
	requireEnv(t, env, "OTEL_EXPORTER_PROMETHEUS_PORT", "9999")
}

func TestBuildEnvVars_MetricsDefaultPort(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Metrics = &pocketidinternalv1alpha1.MetricsConfig{Enabled: true}

	env := buildEnvVars(inst)
	requireEnv(t, env, "OTEL_EXPORTER_PROMETHEUS_PORT", "9464")
}

func TestBuildEnvVars_MetricsDisabled(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Metrics = &pocketidinternalv1alpha1.MetricsConfig{Enabled: false}

	env := buildEnvVars(inst)
	requireEnvAbsent(t, env, "METRICS_ENABLED")
}

func TestBuildEnvVars_UI(t *testing.T) {
	inst := minimalInstance()
	sessionDuration := int32(1440)
	inst.Spec.UI = &pocketidinternalv1alpha1.UIConfig{
		AppName:           "My SSO",
		SessionDuration:   &sessionDuration,
		HomePageURL:       "/dashboard",
		DisableAnimations: true,
		AccentColor:       "#3b82f6",
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "APP_NAME", "My SSO")
	requireEnv(t, env, "SESSION_DURATION", "1440")
	requireEnv(t, env, "HOME_PAGE_URL", "/dashboard")
	requireEnv(t, env, "DISABLE_ANIMATIONS", "true")
	requireEnv(t, env, "ACCENT_COLOR", "#3b82f6")
}

func TestBuildEnvVars_UserManagement(t *testing.T) {
	inst := minimalInstance()
	allowEdit := false
	inst.Spec.UserManagement = &pocketidinternalv1alpha1.UserManagementConfig{
		EmailsVerified:            true,
		AllowOwnAccountEdit:       &allowEdit,
		AllowUserSignups:          "withToken",
		SignupDefaultCustomClaims: `[{"key":"role","value":"user"}]`,
		SignupDefaultUserGroupIDs: []string{"uuid-1", "uuid-2"},
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "EMAILS_VERIFIED", "true")
	requireEnv(t, env, "ALLOW_OWN_ACCOUNT_EDIT", "false")
	requireEnv(t, env, "ALLOW_USER_SIGNUPS", "withToken")
	requireEnv(t, env, "SIGNUP_DEFAULT_CUSTOM_CLAIMS", `[{"key":"role","value":"user"}]`)
	requireEnv(t, env, "SIGNUP_DEFAULT_USER_GROUP_IDS", "uuid-1,uuid-2")
}

func TestBuildEnvVars_GeoIP(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.GeoIP = &pocketidinternalv1alpha1.GeoIPConfig{
		MaxmindLicenseKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "my-key"},
		DBPath:            "/data/GeoLite2.mmdb",
		DBURL:             &pocketidinternalv1alpha1.SensitiveValue{Value: "https://custom.example.com/db"},
	}

	env := buildEnvVars(inst)
	requireEnv(t, env, "MAXMIND_LICENSE_KEY", "my-key")
	requireEnv(t, env, "GEOLITE_DB_PATH", "/data/GeoLite2.mmdb")
	requireEnv(t, env, "GEOLITE_DB_URL", "https://custom.example.com/db")
}

func TestBuildEnvVars_StandaloneSettings(t *testing.T) {
	inst := minimalInstance()
	retention := int32(30)
	inst.Spec.AuditLogRetentionDays = &retention
	inst.Spec.AnalyticsDisabled = true
	inst.Spec.VersionCheckDisabled = true
	inst.Spec.InternalAppURL = "http://pocket-id.pocket-id.svc:1411"

	env := buildEnvVars(inst)
	requireEnv(t, env, "AUDIT_LOG_RETENTION_DAYS", "30")
	requireEnv(t, env, "ANALYTICS_DISABLED", "true")
	requireEnv(t, env, "VERSION_CHECK_DISABLED", "true")
	requireEnv(t, env, "INTERNAL_APP_URL", "http://pocket-id.pocket-id.svc:1411")
}

func TestBuildEnvVars_LocalIPv6Ranges(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.LocalIPv6Ranges = "fd00::/8,fe80::/10"

	env := buildEnvVars(inst)
	requireEnv(t, env, "LOCAL_IPV6_RANGES", "fd00::/8,fe80::/10")
}

func TestBuildEnvVars_Timezone(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Timezone = "America/New_York"

	env := buildEnvVars(inst)
	requireEnv(t, env, "TZ", "America/New_York")
}

func TestBuildEnvVars_StandaloneSettingsAbsentByDefault(t *testing.T) {
	inst := minimalInstance()
	env := buildEnvVars(inst)
	requireEnvAbsent(t, env, "AUDIT_LOG_RETENTION_DAYS")
	requireEnvAbsent(t, env, "ANALYTICS_DISABLED")
	requireEnvAbsent(t, env, "VERSION_CHECK_DISABLED")
	requireEnvAbsent(t, env, "INTERNAL_APP_URL")
	requireEnvAbsent(t, env, "LOCAL_IPV6_RANGES")
	requireEnvAbsent(t, env, "TZ")
}

func TestBuildEnvVars_UserEnvOverrides(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Logging = &pocketidinternalv1alpha1.LoggingConfig{Level: "info"}
	// User overrides LOG_LEVEL via spec.env
	inst.Spec.Env = []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "debug"},
		{Name: "CUSTOM_VAR", Value: "custom-value"},
	}

	env := buildEnvVars(inst)

	// The user's override should appear after the operator-set value
	// (last writer wins for k8s env vars)
	requireEnv(t, env, "CUSTOM_VAR", "custom-value")

	// Both should be present; k8s uses the last one
	count := 0
	for _, e := range env {
		if e.Name == "LOG_LEVEL" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected LOG_LEVEL to appear twice (operator + user override), got %d", count)
	}
	// Last one should be the user's override
	if env[len(env)-2].Name == "LOG_LEVEL" && env[len(env)-2].Value != "debug" {
		t.Errorf("expected user override to be last LOG_LEVEL")
	}
}

func TestSensitiveValueToEnvVar_PlainValue(t *testing.T) {
	sv := &pocketidinternalv1alpha1.SensitiveValue{Value: "plain-text"}
	e := sensitiveValueToEnvVar("TEST_VAR", sv)
	if e.Name != "TEST_VAR" {
		t.Errorf("name: got %q, want %q", e.Name, "TEST_VAR")
	}
	if e.Value != "plain-text" {
		t.Errorf("value: got %q, want %q", e.Value, "plain-text")
	}
	if e.ValueFrom != nil {
		t.Error("expected ValueFrom to be nil for plain value")
	}
}

func TestSensitiveValueToEnvVar_SecretRef(t *testing.T) {
	sv := &pocketidinternalv1alpha1.SensitiveValue{
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
				Key:                  "my-key",
			},
		},
	}
	e := sensitiveValueToEnvVar("TEST_VAR", sv)
	if e.Value != "" {
		t.Errorf("expected empty Value when using ValueFrom, got %q", e.Value)
	}
	if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
		t.Fatal("expected secretKeyRef to be set")
	}
	if e.ValueFrom.SecretKeyRef.Name != "my-secret" {
		t.Errorf("secret name: got %q, want %q", e.ValueFrom.SecretKeyRef.Name, "my-secret")
	}
}
