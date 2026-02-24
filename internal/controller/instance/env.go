package instance

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

// buildEnvVars constructs the full list of environment variables for a PocketIDInstance container.
// Order matters: operator-managed vars first, then spec-derived vars, then user's spec.env last (can override).
func buildEnvVars(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	env := buildCoreEnv(instance)
	env = append(env, buildMetricsEnv(instance)...)
	env = append(env, buildS3Env(instance)...)
	env = append(env, buildSMTPEnv(instance)...)
	env = append(env, buildEmailNotificationsEnv(instance)...)
	env = append(env, buildLDAPEnv(instance)...)
	env = append(env, buildLoggingEnv(instance)...)
	env = append(env, buildTracingEnv(instance)...)
	env = append(env, buildUIEnv(instance)...)
	env = append(env, buildUserManagementEnv(instance)...)
	env = append(env, buildGeoIPEnv(instance)...)
	env = append(env, buildStandaloneEnv(instance)...)

	// User-provided env vars applied last so they can override anything above
	env = append(env, instance.Spec.Env...)

	return env
}

func buildCoreEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	encryptionKeyEnv := corev1.EnvVar{Name: envEncryptionKey}
	if instance.Spec.EncryptionKey.Value != "" {
		encryptionKeyEnv.Value = instance.Spec.EncryptionKey.Value
	} else if instance.Spec.EncryptionKey.ValueFrom != nil {
		encryptionKeyEnv.ValueFrom = instance.Spec.EncryptionKey.ValueFrom
	}

	env := []corev1.EnvVar{
		encryptionKeyEnv,
		{Name: envTrustProxy, Value: "true"},
	}

	if instance.Spec.DatabaseUrl != nil {
		dbUrlEnv := corev1.EnvVar{Name: envDBConnectionString}
		if instance.Spec.DatabaseUrl.Value != "" {
			dbUrlEnv.Value = instance.Spec.DatabaseUrl.Value
		} else if instance.Spec.DatabaseUrl.ValueFrom != nil {
			dbUrlEnv.ValueFrom = instance.Spec.DatabaseUrl.ValueFrom
		}
		env = append(env, dbUrlEnv)
	}

	if instance.Spec.AppURL != "" {
		env = append(env, corev1.EnvVar{Name: envAppURL, Value: instance.Spec.AppURL})
	}

	env = append(env,
		corev1.EnvVar{Name: "DISABLE_RATE_LIMITING", Value: "true"},
		corev1.EnvVar{Name: "UI_CONFIG_DISABLED", Value: "true"},
	)

	// Static API key for operator authentication
	staticAPIKeySecret := common.StaticAPIKeySecretName(instance.Name)
	env = append(env, corev1.EnvVar{
		Name: envStaticAPIKey,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: staticAPIKeySecret,
				},
				Key: "token",
			},
		},
	})

	return env
}

func buildMetricsEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.Metrics == nil || !instance.Spec.Metrics.Enabled {
		return nil
	}
	metricsPort := int32(9464)
	if instance.Spec.Metrics.Port != 0 {
		metricsPort = instance.Spec.Metrics.Port
	}
	return []corev1.EnvVar{
		{Name: "METRICS_ENABLED", Value: "true"},
		{Name: "OTEL_METRICS_EXPORTER", Value: "prometheus"},
		{Name: "OTEL_EXPORTER_PROMETHEUS_HOST", Value: "0.0.0.0"},
		{Name: "OTEL_EXPORTER_PROMETHEUS_PORT", Value: fmt.Sprintf("%d", metricsPort)},
	}
}

func buildS3Env(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.S3 == nil {
		return nil
	}
	s3 := instance.Spec.S3
	env := []corev1.EnvVar{
		{Name: "FILE_BACKEND", Value: "s3"},
		{Name: "S3_BUCKET", Value: s3.Bucket},
		{Name: "S3_REGION", Value: s3.Region},
	}
	if s3.Endpoint != "" {
		env = append(env, corev1.EnvVar{Name: "S3_ENDPOINT", Value: s3.Endpoint})
	}
	env = append(env, sensitiveValueToEnvVar("S3_ACCESS_KEY_ID", &s3.AccessKeyID))
	env = append(env, sensitiveValueToEnvVar("S3_SECRET_ACCESS_KEY", &s3.SecretAccessKey))
	if s3.ForcePathStyle {
		env = append(env, corev1.EnvVar{Name: "S3_FORCE_PATH_STYLE", Value: "true"})
	}
	return env
}

func buildSMTPEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.SMTP == nil {
		return nil
	}
	smtp := instance.Spec.SMTP
	env := []corev1.EnvVar{
		{Name: "SMTP_ENABLED", Value: "true"},
		{Name: "SMTP_HOST", Value: smtp.Host},
		{Name: "SMTP_PORT", Value: fmt.Sprintf("%d", smtp.Port)},
		{Name: "SMTP_FROM", Value: smtp.From},
	}
	if smtp.User != "" {
		env = append(env, corev1.EnvVar{Name: "SMTP_USER", Value: smtp.User})
	}
	if smtp.Password != nil {
		env = append(env, sensitiveValueToEnvVar("SMTP_PASSWORD", smtp.Password))
	}
	if smtp.TLS != "" {
		env = append(env, corev1.EnvVar{Name: "SMTP_TLS", Value: smtp.TLS})
	}
	if smtp.SkipCertVerify {
		env = append(env, corev1.EnvVar{Name: "SMTP_SKIP_CERT_VERIFY", Value: "true"})
	}
	return env
}

func buildEmailNotificationsEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.EmailNotifications == nil {
		return nil
	}
	en := instance.Spec.EmailNotifications
	var env []corev1.EnvVar
	if en.LoginNotification {
		env = append(env, corev1.EnvVar{Name: "EMAIL_LOGIN_NOTIFICATION_ENABLED", Value: "true"})
	}
	if en.OneTimeAccessAsAdmin {
		env = append(env, corev1.EnvVar{Name: "EMAIL_ONE_TIME_ACCESS_AS_ADMIN_ENABLED", Value: "true"})
	}
	if en.APIKeyExpiration {
		env = append(env, corev1.EnvVar{Name: "EMAIL_API_KEY_EXPIRATION_ENABLED", Value: "true"})
	}
	if en.OneTimeAccessAsUnauthenticated {
		env = append(env, corev1.EnvVar{Name: "EMAIL_ONE_TIME_ACCESS_AS_UNAUTHENTICATED_ENABLED", Value: "true"})
	}
	if en.Verification {
		env = append(env, corev1.EnvVar{Name: "EMAIL_VERIFICATION_ENABLED", Value: "true"})
	}
	return env
}

func buildLDAPEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.LDAP == nil {
		return nil
	}
	ldap := instance.Spec.LDAP
	env := []corev1.EnvVar{
		{Name: "LDAP_ENABLED", Value: "true"},
		{Name: "LDAP_URL", Value: ldap.URL},
		{Name: "LDAP_BIND_DN", Value: ldap.BindDN},
		sensitiveValueToEnvVar("LDAP_BIND_PASSWORD", &ldap.BindPassword),
		{Name: "LDAP_BASE", Value: ldap.Base},
	}
	if ldap.SkipCertVerify {
		env = append(env, corev1.EnvVar{Name: "LDAP_SKIP_CERT_VERIFY", Value: "true"})
	}
	if ldap.SoftDeleteUsers {
		env = append(env, corev1.EnvVar{Name: "LDAP_SOFT_DELETE_USERS", Value: "true"})
	}
	if ldap.AdminGroupName != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ADMIN_GROUP_NAME", Value: ldap.AdminGroupName})
	}
	if ldap.UserSearchFilter != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_USER_SEARCH_FILTER", Value: ldap.UserSearchFilter})
	}
	if ldap.UserGroupSearchFilter != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_USER_GROUP_SEARCH_FILTER", Value: ldap.UserGroupSearchFilter})
	}
	if ldap.AttributeMapping != nil {
		env = append(env, buildLDAPAttributeMappingEnv(ldap.AttributeMapping)...)
	}
	return env
}

func buildLDAPAttributeMappingEnv(am *pocketidinternalv1alpha1.LDAPAttributeMappingConfig) []corev1.EnvVar {
	var env []corev1.EnvVar
	if am.UserUniqueIdentifier != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_USER_UNIQUE_IDENTIFIER", Value: am.UserUniqueIdentifier})
	}
	if am.UserUsername != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_USER_USERNAME", Value: am.UserUsername})
	}
	if am.UserEmail != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_USER_EMAIL", Value: am.UserEmail})
	}
	if am.UserFirstName != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_USER_FIRST_NAME", Value: am.UserFirstName})
	}
	if am.UserLastName != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_USER_LAST_NAME", Value: am.UserLastName})
	}
	if am.UserProfilePicture != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_USER_PROFILE_PICTURE", Value: am.UserProfilePicture})
	}
	if am.GroupMember != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_GROUP_MEMBER", Value: am.GroupMember})
	}
	if am.GroupUniqueIdentifier != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_GROUP_UNIQUE_IDENTIFIER", Value: am.GroupUniqueIdentifier})
	}
	if am.GroupName != "" {
		env = append(env, corev1.EnvVar{Name: "LDAP_ATTRIBUTE_GROUP_NAME", Value: am.GroupName})
	}
	return env
}

func buildLoggingEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.Logging == nil {
		return nil
	}
	var env []corev1.EnvVar
	if instance.Spec.Logging.Level != "" {
		env = append(env, corev1.EnvVar{Name: "LOG_LEVEL", Value: instance.Spec.Logging.Level})
	}
	if instance.Spec.Logging.JSON {
		env = append(env, corev1.EnvVar{Name: "LOG_JSON", Value: "true"})
	}
	return env
}

func buildTracingEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.Tracing == nil {
		return nil
	}
	return []corev1.EnvVar{
		{Name: "TRACING_ENABLED", Value: "true"},
	}
}

func buildUIEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.UI == nil {
		return nil
	}
	ui := instance.Spec.UI
	var env []corev1.EnvVar
	if ui.AppName != "" {
		env = append(env, corev1.EnvVar{Name: "APP_NAME", Value: ui.AppName})
	}
	if ui.SessionDuration != nil {
		env = append(env, corev1.EnvVar{Name: "SESSION_DURATION", Value: fmt.Sprintf("%d", *ui.SessionDuration)})
	}
	if ui.HomePageURL != "" {
		env = append(env, corev1.EnvVar{Name: "HOME_PAGE_URL", Value: ui.HomePageURL})
	}
	if ui.DisableAnimations {
		env = append(env, corev1.EnvVar{Name: "DISABLE_ANIMATIONS", Value: "true"})
	}
	if ui.AccentColor != "" {
		env = append(env, corev1.EnvVar{Name: "ACCENT_COLOR", Value: ui.AccentColor})
	}
	return env
}

func buildUserManagementEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.UserManagement == nil {
		return nil
	}
	um := instance.Spec.UserManagement
	var env []corev1.EnvVar
	if um.EmailsVerified {
		env = append(env, corev1.EnvVar{Name: "EMAILS_VERIFIED", Value: "true"})
	}
	if um.AllowOwnAccountEdit != nil {
		env = append(env, corev1.EnvVar{Name: "ALLOW_OWN_ACCOUNT_EDIT", Value: fmt.Sprintf("%t", *um.AllowOwnAccountEdit)})
	}
	if um.AllowUserSignups != "" {
		env = append(env, corev1.EnvVar{Name: "ALLOW_USER_SIGNUPS", Value: um.AllowUserSignups})
	}
	if um.SignupDefaultCustomClaims != "" {
		env = append(env, corev1.EnvVar{Name: "SIGNUP_DEFAULT_CUSTOM_CLAIMS", Value: um.SignupDefaultCustomClaims})
	}
	if len(um.SignupDefaultUserGroupIDs) > 0 {
		env = append(env, corev1.EnvVar{Name: "SIGNUP_DEFAULT_USER_GROUP_IDS", Value: strings.Join(um.SignupDefaultUserGroupIDs, ",")})
	}
	return env
}

func buildGeoIPEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	if instance.Spec.GeoIP == nil {
		return nil
	}
	geo := instance.Spec.GeoIP
	var env []corev1.EnvVar
	if geo.MaxmindLicenseKey != nil {
		env = append(env, sensitiveValueToEnvVar("MAXMIND_LICENSE_KEY", geo.MaxmindLicenseKey))
	}
	if geo.DBPath != "" {
		env = append(env, corev1.EnvVar{Name: "GEOLITE_DB_PATH", Value: geo.DBPath})
	}
	if geo.DBURL != "" {
		env = append(env, corev1.EnvVar{Name: "GEOLITE_DB_URL", Value: geo.DBURL})
	}
	return env
}

func buildStandaloneEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	var env []corev1.EnvVar
	if instance.Spec.AuditLogRetentionDays != nil {
		env = append(env, corev1.EnvVar{Name: "AUDIT_LOG_RETENTION_DAYS", Value: fmt.Sprintf("%d", *instance.Spec.AuditLogRetentionDays)})
	}
	if instance.Spec.AnalyticsDisabled {
		env = append(env, corev1.EnvVar{Name: "ANALYTICS_DISABLED", Value: "true"})
	}
	if instance.Spec.VersionCheckDisabled {
		env = append(env, corev1.EnvVar{Name: "VERSION_CHECK_DISABLED", Value: "true"})
	}
	if instance.Spec.InternalAppURL != "" {
		env = append(env, corev1.EnvVar{Name: "INTERNAL_APP_URL", Value: instance.Spec.InternalAppURL})
	}
	return env
}

// sensitiveValueToEnvVar converts a SensitiveValue to a corev1.EnvVar.
func sensitiveValueToEnvVar(name string, sv *pocketidinternalv1alpha1.SensitiveValue) corev1.EnvVar {
	e := corev1.EnvVar{Name: name}
	if sv.ValueFrom != nil {
		e.ValueFrom = sv.ValueFrom
	} else {
		e.Value = sv.Value
	}
	return e
}
