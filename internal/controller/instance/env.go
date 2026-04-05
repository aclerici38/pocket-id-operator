package instance

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

// buildEnvVars constructs the full list of environment variables for a PocketIDInstance container.
// Order matters: operator-managed vars first, then spec-derived vars, then user's spec.env last (can override).
func buildEnvVars(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	env := buildCoreEnv(instance)
	env = append(env, buildMetricsEnv(instance)...)
	env = append(env, buildFileBackendEnv(instance)...)
	env = append(env, buildS3Env(instance)...)
	env = append(env, buildLoggingEnv(instance)...)
	env = append(env, buildTracingEnv(instance)...)
	env = append(env, buildGeoIPEnv(instance)...)
	env = append(env, buildStandaloneEnv(instance)...)

	// User-provided env vars applied last so they can override anything above
	env = append(env, instance.Spec.Env...)

	return env
}

func buildCoreEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	env := []corev1.EnvVar{
		sensitiveValueToEnvVar(envEncryptionKey, &instance.Spec.EncryptionKey),
		{Name: envTrustProxy, Value: "true"},
	}

	if instance.Spec.DatabaseUrl != nil {
		env = append(env, sensitiveValueToEnvVar(envDBConnectionString, instance.Spec.DatabaseUrl))
	}

	if instance.Spec.AppURL != "" {
		env = append(env, corev1.EnvVar{Name: envAppURL, Value: instance.Spec.AppURL})
	}

	env = append(env, corev1.EnvVar{Name: "DISABLE_RATE_LIMITING", Value: "true"})

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

func buildFileBackendEnv(instance *pocketidinternalv1alpha1.PocketIDInstance) []corev1.EnvVar {
	// When S3 config is present, buildS3Env sets FILE_BACKEND=s3
	if instance.Spec.S3 != nil {
		return nil
	}
	if instance.Spec.FileBackend != "" {
		return []corev1.EnvVar{
			{Name: "FILE_BACKEND", Value: instance.Spec.FileBackend},
		}
	}
	return nil
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
	if s3.DisableDefaultIntegrityChecks {
		env = append(env, corev1.EnvVar{Name: "S3_DISABLE_DEFAULT_INTEGRITY_CHECKS", Value: "true"})
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
	if geo.DBURL != nil {
		env = append(env, sensitiveValueToEnvVar("GEOLITE_DB_URL", geo.DBURL))
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
	if instance.Spec.LocalIPv6Ranges != "" {
		env = append(env, corev1.EnvVar{Name: "LOCAL_IPV6_RANGES", Value: instance.Spec.LocalIPv6Ranges})
	}
	if instance.Spec.Timezone != "" {
		env = append(env, corev1.EnvVar{Name: "TZ", Value: instance.Spec.Timezone})
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
