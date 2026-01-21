package instance

import (
	corev1 "k8s.io/api/core/v1"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
)

func envVarApplyConfigurationValues(envs []corev1.EnvVar) []corev1apply.EnvVarApplyConfiguration {
	if len(envs) == 0 {
		return nil
	}

	out := make([]corev1apply.EnvVarApplyConfiguration, 0, len(envs))
	for _, env := range envs {
		cfg := corev1apply.EnvVar().WithName(env.Name)
		if env.ValueFrom != nil {
			cfg.WithValueFrom(envVarSourceApplyConfiguration(env.ValueFrom))
		} else if env.Value != "" {
			cfg.WithValue(env.Value)
		}
		out = append(out, *cfg)
	}

	return out
}

func envVarSourceApplyConfiguration(source *corev1.EnvVarSource) *corev1apply.EnvVarSourceApplyConfiguration {
	if source == nil {
		return nil
	}

	cfg := corev1apply.EnvVarSource()
	if source.FieldRef != nil {
		cfg.WithFieldRef(objectFieldSelectorApplyConfiguration(source.FieldRef))
	}
	if source.ResourceFieldRef != nil {
		cfg.WithResourceFieldRef(resourceFieldSelectorApplyConfiguration(source.ResourceFieldRef))
	}
	if source.ConfigMapKeyRef != nil {
		cfg.WithConfigMapKeyRef(configMapKeySelectorApplyConfiguration(source.ConfigMapKeyRef))
	}
	if source.SecretKeyRef != nil {
		cfg.WithSecretKeyRef(secretKeySelectorApplyConfiguration(source.SecretKeyRef))
	}
	if source.FileKeyRef != nil {
		cfg.WithFileKeyRef(fileKeySelectorApplyConfiguration(source.FileKeyRef))
	}

	return cfg
}

func objectFieldSelectorApplyConfiguration(selector *corev1.ObjectFieldSelector) *corev1apply.ObjectFieldSelectorApplyConfiguration {
	if selector == nil {
		return nil
	}

	cfg := corev1apply.ObjectFieldSelector()
	if selector.APIVersion != "" {
		cfg.WithAPIVersion(selector.APIVersion)
	}
	if selector.FieldPath != "" {
		cfg.WithFieldPath(selector.FieldPath)
	}

	return cfg
}

func resourceFieldSelectorApplyConfiguration(selector *corev1.ResourceFieldSelector) *corev1apply.ResourceFieldSelectorApplyConfiguration {
	if selector == nil {
		return nil
	}

	cfg := corev1apply.ResourceFieldSelector()
	if selector.ContainerName != "" {
		cfg.WithContainerName(selector.ContainerName)
	}
	if selector.Resource != "" {
		cfg.WithResource(selector.Resource)
	}
	if !selector.Divisor.IsZero() {
		cfg.WithDivisor(selector.Divisor)
	}

	return cfg
}

func configMapKeySelectorApplyConfiguration(selector *corev1.ConfigMapKeySelector) *corev1apply.ConfigMapKeySelectorApplyConfiguration {
	if selector == nil {
		return nil
	}

	cfg := corev1apply.ConfigMapKeySelector()
	if selector.Name != "" {
		cfg.WithName(selector.Name)
	}
	if selector.Key != "" {
		cfg.WithKey(selector.Key)
	}
	if selector.Optional != nil {
		cfg.WithOptional(*selector.Optional)
	}

	return cfg
}

func secretKeySelectorApplyConfiguration(selector *corev1.SecretKeySelector) *corev1apply.SecretKeySelectorApplyConfiguration {
	if selector == nil {
		return nil
	}

	cfg := corev1apply.SecretKeySelector()
	if selector.Name != "" {
		cfg.WithName(selector.Name)
	}
	if selector.Key != "" {
		cfg.WithKey(selector.Key)
	}
	if selector.Optional != nil {
		cfg.WithOptional(*selector.Optional)
	}

	return cfg
}

func fileKeySelectorApplyConfiguration(selector *corev1.FileKeySelector) *corev1apply.FileKeySelectorApplyConfiguration {
	if selector == nil {
		return nil
	}

	cfg := corev1apply.FileKeySelector()
	if selector.VolumeName != "" {
		cfg.WithVolumeName(selector.VolumeName)
	}
	if selector.Path != "" {
		cfg.WithPath(selector.Path)
	}
	if selector.Key != "" {
		cfg.WithKey(selector.Key)
	}
	if selector.Optional != nil {
		cfg.WithOptional(*selector.Optional)
	}

	return cfg
}

func volumeMountApplyConfigurationValues(mounts []corev1.VolumeMount) []corev1apply.VolumeMountApplyConfiguration {
	if len(mounts) == 0 {
		return nil
	}

	out := make([]corev1apply.VolumeMountApplyConfiguration, 0, len(mounts))
	for _, mount := range mounts {
		cfg := corev1apply.VolumeMount().
			WithName(mount.Name).
			WithMountPath(mount.MountPath)
		if mount.ReadOnly {
			cfg.WithReadOnly(mount.ReadOnly)
		}
		if mount.RecursiveReadOnly != nil {
			cfg.WithRecursiveReadOnly(*mount.RecursiveReadOnly)
		}
		if mount.SubPath != "" {
			cfg.WithSubPath(mount.SubPath)
		}
		if mount.SubPathExpr != "" {
			cfg.WithSubPathExpr(mount.SubPathExpr)
		}
		if mount.MountPropagation != nil {
			cfg.WithMountPropagation(*mount.MountPropagation)
		}

		out = append(out, *cfg)
	}

	return out
}

func volumeApplyConfigurationValues(volumes []corev1.Volume) []corev1apply.VolumeApplyConfiguration {
	if len(volumes) == 0 {
		return nil
	}

	out := make([]corev1apply.VolumeApplyConfiguration, 0, len(volumes))
	for _, volume := range volumes {
		cfg := corev1apply.Volume().WithName(volume.Name)
		if volume.EmptyDir != nil {
			cfg.WithEmptyDir(emptyDirVolumeSourceApplyConfiguration(volume.EmptyDir))
		}
		if volume.PersistentVolumeClaim != nil {
			cfg.WithPersistentVolumeClaim(persistentVolumeClaimVolumeSourceApplyConfiguration(volume.PersistentVolumeClaim))
		}

		out = append(out, *cfg)
	}

	return out
}

func emptyDirVolumeSourceApplyConfiguration(source *corev1.EmptyDirVolumeSource) *corev1apply.EmptyDirVolumeSourceApplyConfiguration {
	if source == nil {
		return nil
	}

	cfg := corev1apply.EmptyDirVolumeSource()
	if source.Medium != "" {
		cfg.WithMedium(source.Medium)
	}
	if source.SizeLimit != nil {
		cfg.WithSizeLimit(*source.SizeLimit)
	}

	return cfg
}

func persistentVolumeClaimVolumeSourceApplyConfiguration(source *corev1.PersistentVolumeClaimVolumeSource) *corev1apply.PersistentVolumeClaimVolumeSourceApplyConfiguration {
	if source == nil {
		return nil
	}

	cfg := corev1apply.PersistentVolumeClaimVolumeSource()
	if source.ClaimName != "" {
		cfg.WithClaimName(source.ClaimName)
	}
	if source.ReadOnly {
		cfg.WithReadOnly(source.ReadOnly)
	}

	return cfg
}

func resourceRequirementsApplyConfiguration(reqs corev1.ResourceRequirements) *corev1apply.ResourceRequirementsApplyConfiguration {
	cfg := corev1apply.ResourceRequirements()
	if len(reqs.Requests) > 0 {
		cfg.WithRequests(reqs.Requests)
	}
	if len(reqs.Limits) > 0 {
		cfg.WithLimits(reqs.Limits)
	}
	return cfg
}

func podSecurityContextApplyConfiguration(ctx *corev1.PodSecurityContext) *corev1apply.PodSecurityContextApplyConfiguration {
	if ctx == nil {
		return nil
	}

	cfg := corev1apply.PodSecurityContext()
	if ctx.SELinuxOptions != nil {
		cfg.WithSELinuxOptions(seLinuxOptionsApplyConfiguration(ctx.SELinuxOptions))
	}
	if ctx.WindowsOptions != nil {
		cfg.WithWindowsOptions(windowsSecurityContextOptionsApplyConfiguration(ctx.WindowsOptions))
	}
	if ctx.RunAsUser != nil {
		cfg.WithRunAsUser(*ctx.RunAsUser)
	}
	if ctx.RunAsGroup != nil {
		cfg.WithRunAsGroup(*ctx.RunAsGroup)
	}
	if ctx.RunAsNonRoot != nil {
		cfg.WithRunAsNonRoot(*ctx.RunAsNonRoot)
	}
	if len(ctx.SupplementalGroups) > 0 {
		cfg.WithSupplementalGroups(ctx.SupplementalGroups...)
	}
	if ctx.SupplementalGroupsPolicy != nil {
		cfg.WithSupplementalGroupsPolicy(*ctx.SupplementalGroupsPolicy)
	}
	if ctx.FSGroup != nil {
		cfg.WithFSGroup(*ctx.FSGroup)
	}
	if len(ctx.Sysctls) > 0 {
		cfg.Sysctls = sysctlApplyConfigurationValues(ctx.Sysctls)
	}
	if ctx.FSGroupChangePolicy != nil {
		cfg.WithFSGroupChangePolicy(*ctx.FSGroupChangePolicy)
	}
	if ctx.SeccompProfile != nil {
		cfg.WithSeccompProfile(seccompProfileApplyConfiguration(ctx.SeccompProfile))
	}
	if ctx.AppArmorProfile != nil {
		cfg.WithAppArmorProfile(appArmorProfileApplyConfiguration(ctx.AppArmorProfile))
	}
	if ctx.SELinuxChangePolicy != nil {
		cfg.WithSELinuxChangePolicy(*ctx.SELinuxChangePolicy)
	}

	return cfg
}

func securityContextApplyConfiguration(ctx *corev1.SecurityContext) *corev1apply.SecurityContextApplyConfiguration {
	if ctx == nil {
		return nil
	}

	cfg := corev1apply.SecurityContext()
	if ctx.Capabilities != nil {
		cfg.WithCapabilities(capabilitiesApplyConfiguration(ctx.Capabilities))
	}
	if ctx.Privileged != nil {
		cfg.WithPrivileged(*ctx.Privileged)
	}
	if ctx.SELinuxOptions != nil {
		cfg.WithSELinuxOptions(seLinuxOptionsApplyConfiguration(ctx.SELinuxOptions))
	}
	if ctx.WindowsOptions != nil {
		cfg.WithWindowsOptions(windowsSecurityContextOptionsApplyConfiguration(ctx.WindowsOptions))
	}
	if ctx.RunAsUser != nil {
		cfg.WithRunAsUser(*ctx.RunAsUser)
	}
	if ctx.RunAsGroup != nil {
		cfg.WithRunAsGroup(*ctx.RunAsGroup)
	}
	if ctx.RunAsNonRoot != nil {
		cfg.WithRunAsNonRoot(*ctx.RunAsNonRoot)
	}
	if ctx.ReadOnlyRootFilesystem != nil {
		cfg.WithReadOnlyRootFilesystem(*ctx.ReadOnlyRootFilesystem)
	}
	if ctx.AllowPrivilegeEscalation != nil {
		cfg.WithAllowPrivilegeEscalation(*ctx.AllowPrivilegeEscalation)
	}
	if ctx.ProcMount != nil {
		cfg.WithProcMount(*ctx.ProcMount)
	}
	if ctx.SeccompProfile != nil {
		cfg.WithSeccompProfile(seccompProfileApplyConfiguration(ctx.SeccompProfile))
	}
	if ctx.AppArmorProfile != nil {
		cfg.WithAppArmorProfile(appArmorProfileApplyConfiguration(ctx.AppArmorProfile))
	}

	return cfg
}

func capabilitiesApplyConfiguration(capabilities *corev1.Capabilities) *corev1apply.CapabilitiesApplyConfiguration {
	if capabilities == nil {
		return nil
	}

	cfg := corev1apply.Capabilities()
	if len(capabilities.Add) > 0 {
		cfg.WithAdd(capabilities.Add...)
	}
	if len(capabilities.Drop) > 0 {
		cfg.WithDrop(capabilities.Drop...)
	}

	return cfg
}

func seLinuxOptionsApplyConfiguration(options *corev1.SELinuxOptions) *corev1apply.SELinuxOptionsApplyConfiguration {
	if options == nil {
		return nil
	}

	cfg := corev1apply.SELinuxOptions()
	if options.User != "" {
		cfg.WithUser(options.User)
	}
	if options.Role != "" {
		cfg.WithRole(options.Role)
	}
	if options.Type != "" {
		cfg.WithType(options.Type)
	}
	if options.Level != "" {
		cfg.WithLevel(options.Level)
	}

	return cfg
}

func windowsSecurityContextOptionsApplyConfiguration(options *corev1.WindowsSecurityContextOptions) *corev1apply.WindowsSecurityContextOptionsApplyConfiguration {
	if options == nil {
		return nil
	}

	cfg := corev1apply.WindowsSecurityContextOptions()
	if options.GMSACredentialSpecName != nil {
		cfg.WithGMSACredentialSpecName(*options.GMSACredentialSpecName)
	}
	if options.GMSACredentialSpec != nil {
		cfg.WithGMSACredentialSpec(*options.GMSACredentialSpec)
	}
	if options.RunAsUserName != nil {
		cfg.WithRunAsUserName(*options.RunAsUserName)
	}
	if options.HostProcess != nil {
		cfg.WithHostProcess(*options.HostProcess)
	}

	return cfg
}

func seccompProfileApplyConfiguration(profile *corev1.SeccompProfile) *corev1apply.SeccompProfileApplyConfiguration {
	if profile == nil {
		return nil
	}

	cfg := corev1apply.SeccompProfile().WithType(profile.Type)
	if profile.LocalhostProfile != nil {
		cfg.WithLocalhostProfile(*profile.LocalhostProfile)
	}

	return cfg
}

func appArmorProfileApplyConfiguration(profile *corev1.AppArmorProfile) *corev1apply.AppArmorProfileApplyConfiguration {
	if profile == nil {
		return nil
	}

	cfg := corev1apply.AppArmorProfile().WithType(profile.Type)
	if profile.LocalhostProfile != nil {
		cfg.WithLocalhostProfile(*profile.LocalhostProfile)
	}

	return cfg
}

func sysctlApplyConfigurationValues(sysctls []corev1.Sysctl) []corev1apply.SysctlApplyConfiguration {
	if len(sysctls) == 0 {
		return nil
	}

	out := make([]corev1apply.SysctlApplyConfiguration, 0, len(sysctls))
	for _, sysctl := range sysctls {
		cfg := corev1apply.Sysctl()
		if sysctl.Name != "" {
			cfg.WithName(sysctl.Name)
		}
		if sysctl.Value != "" {
			cfg.WithValue(sysctl.Value)
		}
		out = append(out, *cfg)
	}

	return out
}

func probeApplyConfiguration(probe *corev1.Probe) *corev1apply.ProbeApplyConfiguration {
	if probe == nil {
		return nil
	}

	cfg := corev1apply.Probe()
	if probe.Exec != nil {
		cfg.WithExec(execActionApplyConfiguration(probe.Exec))
	}
	if probe.HTTPGet != nil {
		cfg.WithHTTPGet(httpGetActionApplyConfiguration(probe.HTTPGet))
	}
	if probe.TCPSocket != nil {
		cfg.WithTCPSocket(tcpSocketActionApplyConfiguration(probe.TCPSocket))
	}
	if probe.GRPC != nil {
		cfg.WithGRPC(grpcActionApplyConfiguration(probe.GRPC))
	}
	if probe.InitialDelaySeconds != 0 {
		cfg.WithInitialDelaySeconds(probe.InitialDelaySeconds)
	}
	if probe.TimeoutSeconds != 0 {
		cfg.WithTimeoutSeconds(probe.TimeoutSeconds)
	}
	if probe.PeriodSeconds != 0 {
		cfg.WithPeriodSeconds(probe.PeriodSeconds)
	}
	if probe.SuccessThreshold != 0 {
		cfg.WithSuccessThreshold(probe.SuccessThreshold)
	}
	if probe.FailureThreshold != 0 {
		cfg.WithFailureThreshold(probe.FailureThreshold)
	}
	if probe.TerminationGracePeriodSeconds != nil {
		cfg.WithTerminationGracePeriodSeconds(*probe.TerminationGracePeriodSeconds)
	}

	return cfg
}

func execActionApplyConfiguration(action *corev1.ExecAction) *corev1apply.ExecActionApplyConfiguration {
	if action == nil {
		return nil
	}

	cfg := corev1apply.ExecAction()
	if len(action.Command) > 0 {
		cfg.WithCommand(action.Command...)
	}

	return cfg
}

func httpGetActionApplyConfiguration(action *corev1.HTTPGetAction) *corev1apply.HTTPGetActionApplyConfiguration {
	if action == nil {
		return nil
	}

	cfg := corev1apply.HTTPGetAction().WithPort(action.Port)
	if action.Path != "" {
		cfg.WithPath(action.Path)
	}
	if action.Host != "" {
		cfg.WithHost(action.Host)
	}
	if action.Scheme != "" {
		cfg.WithScheme(action.Scheme)
	}
	if len(action.HTTPHeaders) > 0 {
		cfg.HTTPHeaders = httpHeaderApplyConfigurationValues(action.HTTPHeaders)
	}

	return cfg
}

func httpHeaderApplyConfigurationValues(headers []corev1.HTTPHeader) []corev1apply.HTTPHeaderApplyConfiguration {
	if len(headers) == 0 {
		return nil
	}

	out := make([]corev1apply.HTTPHeaderApplyConfiguration, 0, len(headers))
	for _, header := range headers {
		cfg := corev1apply.HTTPHeader()
		if header.Name != "" {
			cfg.WithName(header.Name)
		}
		if header.Value != "" {
			cfg.WithValue(header.Value)
		}
		out = append(out, *cfg)
	}

	return out
}

func tcpSocketActionApplyConfiguration(action *corev1.TCPSocketAction) *corev1apply.TCPSocketActionApplyConfiguration {
	if action == nil {
		return nil
	}

	cfg := corev1apply.TCPSocketAction().WithPort(action.Port)
	if action.Host != "" {
		cfg.WithHost(action.Host)
	}

	return cfg
}

func grpcActionApplyConfiguration(action *corev1.GRPCAction) *corev1apply.GRPCActionApplyConfiguration {
	if action == nil {
		return nil
	}

	cfg := corev1apply.GRPCAction().WithPort(action.Port)
	if action.Service != nil {
		cfg.WithService(*action.Service)
	}

	return cfg
}
