package instance

import (
	"context"
	"fmt"
	"strings"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

// hasAppConfigFields returns true if any spec section that should be managed
// via the application configuration API is set.
func hasAppConfigFields(instance *pocketidinternalv1alpha1.PocketIDInstance) bool {
	return instance.Spec.UI != nil ||
		instance.Spec.UserManagement != nil ||
		instance.Spec.SMTP != nil ||
		instance.Spec.EmailNotifications != nil ||
		instance.Spec.LDAP != nil
}

// reconcileAppConfig reads the current application configuration from the Pocket-ID API,
// merges the operator-managed fields from the CRD spec on top, and pushes the result
// back if anything changed. Fields not managed by the CRD are preserved as-is.
func (r *Reconciler) reconcileAppConfig(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	if !hasAppConfigFields(instance) {
		return nil
	}

	log := logf.FromContext(ctx)

	apiClient, err := common.GetAPIClient(ctx, r.Client, r.APIReader, instance)
	if err != nil {
		return err
	}

	current, err := apiClient.GetAppConfig(ctx)
	if err != nil {
		return fmt.Errorf("get app config: %w", err)
	}

	desired, err := r.buildDesiredAppConfig(ctx, instance, current)
	if err != nil {
		return fmt.Errorf("build desired app config: %w", err)
	}

	if !appConfigNeedsUpdate(current, desired) {
		log.V(1).Info("Application configuration is up to date")
		return nil
	}

	log.Info("Updating application configuration via API")
	if _, err := apiClient.UpdateAppConfig(ctx, desired); err != nil {
		return fmt.Errorf("update app config: %w", err)
	}

	return nil
}

// buildDesiredAppConfig constructs the full AppConfigUpdateDto by starting from
// the current config (to preserve unmanaged fields) and overlaying CRD-managed values.
func (r *Reconciler) buildDesiredAppConfig(
	ctx context.Context,
	instance *pocketidinternalv1alpha1.PocketIDInstance,
	current pocketid.AppConfig,
) (*models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto, error) {
	// Start with current values for all required fields
	dto := &models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto{
		AppName:                                   strPtr(current["appName"]),
		SessionDuration:                           strPtr(current["sessionDuration"]),
		HomePageURL:                               strPtr(current["homePageUrl"]),
		DisableAnimations:                         strPtr(current["disableAnimations"]),
		AccentColor:                               current["accentColor"],
		AllowOwnAccountEdit:                       strPtr(current["allowOwnAccountEdit"]),
		AllowUserSignups:                          strPtr(current["allowUserSignups"]),
		EmailsVerified:                            strPtr(current["emailsVerified"]),
		SignupDefaultCustomClaims:                 current["signupDefaultCustomClaims"],
		SignupDefaultUserGroupIDs:                 current["signupDefaultUserGroupIDs"],
		SMTPHost:                                  current["smtpHost"],
		SMTPPort:                                  current["smtpPort"],
		SMTPFrom:                                  current["smtpFrom"],
		SMTPUser:                                  current["smtpUser"],
		SMTPPassword:                              current["smtpPassword"],
		SMTPTLS:                                   strPtr(current["smtpTls"]),
		SMTPSkipCertVerify:                        current["smtpSkipCertVerify"],
		EmailLoginNotificationEnabled:             strPtr(current["emailLoginNotificationEnabled"]),
		EmailOneTimeAccessAsAdminEnabled:          strPtr(current["emailOneTimeAccessAsAdminEnabled"]),
		EmailAPIKeyExpirationEnabled:              strPtr(current["emailApiKeyExpirationEnabled"]),
		EmailOneTimeAccessAsUnauthenticatedEnabled: strPtr(current["emailOneTimeAccessAsUnauthenticatedEnabled"]),
		EmailVerificationEnabled:                  strPtr(current["emailVerificationEnabled"]),
		LdapEnabled:                               strPtr(current["ldapEnabled"]),
		LdapURL:                                   current["ldapUrl"],
		LdapBindDn:                                current["ldapBindDn"],
		LdapBindPassword:                          current["ldapBindPassword"],
		LdapBase:                                  current["ldapBase"],
		LdapSkipCertVerify:                        current["ldapSkipCertVerify"],
		LdapSoftDeleteUsers:                       current["ldapSoftDeleteUsers"],
		LdapAdminGroupName:                        current["ldapAdminGroupName"],
		LdapUserSearchFilter:                      current["ldapUserSearchFilter"],
		LdapUserGroupSearchFilter:                 current["ldapUserGroupSearchFilter"],
		LdapAttributeUserUniqueIdentifier:         current["ldapAttributeUserUniqueIdentifier"],
		LdapAttributeUserUsername:                  current["ldapAttributeUserUsername"],
		LdapAttributeUserEmail:                    current["ldapAttributeUserEmail"],
		LdapAttributeUserFirstName:                current["ldapAttributeUserFirstName"],
		LdapAttributeUserLastName:                 current["ldapAttributeUserLastName"],
		LdapAttributeUserDisplayName:              current["ldapAttributeUserDisplayName"],
		LdapAttributeUserProfilePicture:           current["ldapAttributeUserProfilePicture"],
		LdapAttributeGroupMember:                  current["ldapAttributeGroupMember"],
		LdapAttributeGroupUniqueIdentifier:        current["ldapAttributeGroupUniqueIdentifier"],
		LdapAttributeGroupName:                    current["ldapAttributeGroupName"],
		RequireUserEmail:                           strPtr(current["requireUserEmail"]),
	}

	// Overlay CRD-managed fields
	r.applyUIConfig(instance, dto)
	r.applyUserManagementConfig(instance, dto)
	if err := r.applySMTPConfig(ctx, instance, dto); err != nil {
		return nil, err
	}
	r.applyEmailNotificationsConfig(instance, dto)
	if err := r.applyLDAPConfig(ctx, instance, dto); err != nil {
		return nil, err
	}

	return dto, nil
}

func (r *Reconciler) applyUIConfig(instance *pocketidinternalv1alpha1.PocketIDInstance, dto *models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto) {
	if instance.Spec.UI == nil {
		return
	}
	ui := instance.Spec.UI
	if ui.AppName != "" {
		dto.AppName = &ui.AppName
	}
	if ui.SessionDuration != nil {
		s := fmt.Sprintf("%d", *ui.SessionDuration)
		dto.SessionDuration = &s
	}
	if ui.HomePageURL != "" {
		dto.HomePageURL = &ui.HomePageURL
	}
	if ui.DisableAnimations != nil {
		dto.DisableAnimations = strPtr(fmt.Sprintf("%t", *ui.DisableAnimations))
	}
	if ui.AccentColor != "" {
		dto.AccentColor = ui.AccentColor
	}
}

func (r *Reconciler) applyUserManagementConfig(instance *pocketidinternalv1alpha1.PocketIDInstance, dto *models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto) {
	if instance.Spec.UserManagement == nil {
		return
	}
	um := instance.Spec.UserManagement
	if um.RequireUserEmail != nil {
		dto.RequireUserEmail = strPtr(fmt.Sprintf("%t", *um.RequireUserEmail))
	}
	if um.EmailsVerified != nil {
		dto.EmailsVerified = strPtr(fmt.Sprintf("%t", *um.EmailsVerified))
	}
	if um.AllowOwnAccountEdit != nil {
		dto.AllowOwnAccountEdit = strPtr(fmt.Sprintf("%t", *um.AllowOwnAccountEdit))
	}
	if um.AllowUserSignups != "" {
		dto.AllowUserSignups = &um.AllowUserSignups
	}
	if um.SignupDefaultCustomClaims != "" {
		dto.SignupDefaultCustomClaims = um.SignupDefaultCustomClaims
	}
	if len(um.SignupDefaultUserGroupIDs) > 0 {
		dto.SignupDefaultUserGroupIDs = strings.Join(um.SignupDefaultUserGroupIDs, ",")
	}
}

func (r *Reconciler) applySMTPConfig(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, dto *models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto) error {
	if instance.Spec.SMTP == nil {
		return nil
	}
	smtp := instance.Spec.SMTP
	dto.SMTPHost = smtp.Host
	dto.SMTPPort = fmt.Sprintf("%d", smtp.Port)
	dto.SMTPFrom = smtp.From
	if smtp.User != "" {
		dto.SMTPUser = smtp.User
	}
	if smtp.Password != nil {
		password, err := helpers.ResolveSensitiveValue(ctx, r.Client, r.APIReader, instance.Namespace, smtp.Password)
		if err != nil {
			return fmt.Errorf("resolve SMTP password: %w", err)
		}
		dto.SMTPPassword = password
	}
	if smtp.TLS != "" {
		dto.SMTPTLS = &smtp.TLS
	}
	if smtp.SkipCertVerify != nil {
		dto.SMTPSkipCertVerify = fmt.Sprintf("%t", *smtp.SkipCertVerify)
	}
	return nil
}

func (r *Reconciler) applyEmailNotificationsConfig(instance *pocketidinternalv1alpha1.PocketIDInstance, dto *models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto) {
	if instance.Spec.EmailNotifications == nil {
		return
	}
	en := instance.Spec.EmailNotifications
	if en.LoginNotification != nil {
		dto.EmailLoginNotificationEnabled = strPtr(fmt.Sprintf("%t", *en.LoginNotification))
	}
	if en.OneTimeAccessAsAdmin != nil {
		dto.EmailOneTimeAccessAsAdminEnabled = strPtr(fmt.Sprintf("%t", *en.OneTimeAccessAsAdmin))
	}
	if en.APIKeyExpiration != nil {
		dto.EmailAPIKeyExpirationEnabled = strPtr(fmt.Sprintf("%t", *en.APIKeyExpiration))
	}
	if en.OneTimeAccessAsUnauthenticated != nil {
		dto.EmailOneTimeAccessAsUnauthenticatedEnabled = strPtr(fmt.Sprintf("%t", *en.OneTimeAccessAsUnauthenticated))
	}
	if en.Verification != nil {
		dto.EmailVerificationEnabled = strPtr(fmt.Sprintf("%t", *en.Verification))
	}
}

func (r *Reconciler) applyLDAPConfig(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, dto *models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto) error {
	if instance.Spec.LDAP == nil {
		return nil
	}
	ldap := instance.Spec.LDAP
	dto.LdapEnabled = strPtr("true")
	dto.LdapURL = ldap.URL
	dto.LdapBindDn = ldap.BindDN
	dto.LdapBase = ldap.Base

	password, err := helpers.ResolveSensitiveValue(ctx, r.Client, r.APIReader, instance.Namespace, &ldap.BindPassword)
	if err != nil {
		return fmt.Errorf("resolve LDAP bind password: %w", err)
	}
	dto.LdapBindPassword = password

	if ldap.SkipCertVerify != nil {
		dto.LdapSkipCertVerify = fmt.Sprintf("%t", *ldap.SkipCertVerify)
	}
	if ldap.SoftDeleteUsers != nil {
		dto.LdapSoftDeleteUsers = fmt.Sprintf("%t", *ldap.SoftDeleteUsers)
	}
	if ldap.AdminGroupName != "" {
		dto.LdapAdminGroupName = ldap.AdminGroupName
	}
	if ldap.UserSearchFilter != "" {
		dto.LdapUserSearchFilter = ldap.UserSearchFilter
	}
	if ldap.UserGroupSearchFilter != "" {
		dto.LdapUserGroupSearchFilter = ldap.UserGroupSearchFilter
	}

	if ldap.AttributeMapping != nil {
		am := ldap.AttributeMapping
		if am.UserUniqueIdentifier != "" {
			dto.LdapAttributeUserUniqueIdentifier = am.UserUniqueIdentifier
		}
		if am.UserUsername != "" {
			dto.LdapAttributeUserUsername = am.UserUsername
		}
		if am.UserEmail != "" {
			dto.LdapAttributeUserEmail = am.UserEmail
		}
		if am.UserFirstName != "" {
			dto.LdapAttributeUserFirstName = am.UserFirstName
		}
		if am.UserLastName != "" {
			dto.LdapAttributeUserLastName = am.UserLastName
		}
		if am.UserDisplayName != "" {
			dto.LdapAttributeUserDisplayName = am.UserDisplayName
		}
		if am.UserProfilePicture != "" {
			dto.LdapAttributeUserProfilePicture = am.UserProfilePicture
		}
		if am.GroupMember != "" {
			dto.LdapAttributeGroupMember = am.GroupMember
		}
		if am.GroupUniqueIdentifier != "" {
			dto.LdapAttributeGroupUniqueIdentifier = am.GroupUniqueIdentifier
		}
		if am.GroupName != "" {
			dto.LdapAttributeGroupName = am.GroupName
		}
	}
	return nil
}

// appConfigNeedsUpdate compares the current config against the desired DTO to
// determine if an update call is needed. It checks only the fields we manage.
func appConfigNeedsUpdate(current pocketid.AppConfig, desired *models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto) bool {
	check := func(key string, desiredVal *string) bool {
		if desiredVal == nil {
			return false
		}
		return current[key] != *desiredVal
	}
	checkStr := func(key, desiredVal string) bool {
		return current[key] != desiredVal
	}

	return check("appName", desired.AppName) ||
		check("sessionDuration", desired.SessionDuration) ||
		check("homePageUrl", desired.HomePageURL) ||
		check("disableAnimations", desired.DisableAnimations) ||
		checkStr("accentColor", desired.AccentColor) ||
		check("allowOwnAccountEdit", desired.AllowOwnAccountEdit) ||
		check("allowUserSignups", desired.AllowUserSignups) ||
		check("emailsVerified", desired.EmailsVerified) ||
		checkStr("signupDefaultCustomClaims", desired.SignupDefaultCustomClaims) ||
		checkStr("signupDefaultUserGroupIDs", desired.SignupDefaultUserGroupIDs) ||
		checkStr("smtpHost", desired.SMTPHost) ||
		checkStr("smtpPort", desired.SMTPPort) ||
		checkStr("smtpFrom", desired.SMTPFrom) ||
		checkStr("smtpUser", desired.SMTPUser) ||
		checkStr("smtpPassword", desired.SMTPPassword) ||
		check("smtpTls", desired.SMTPTLS) ||
		checkStr("smtpSkipCertVerify", desired.SMTPSkipCertVerify) ||
		check("emailLoginNotificationEnabled", desired.EmailLoginNotificationEnabled) ||
		check("emailOneTimeAccessAsAdminEnabled", desired.EmailOneTimeAccessAsAdminEnabled) ||
		check("emailApiKeyExpirationEnabled", desired.EmailAPIKeyExpirationEnabled) ||
		check("emailOneTimeAccessAsUnauthenticatedEnabled", desired.EmailOneTimeAccessAsUnauthenticatedEnabled) ||
		check("emailVerificationEnabled", desired.EmailVerificationEnabled) ||
		check("ldapEnabled", desired.LdapEnabled) ||
		checkStr("ldapUrl", desired.LdapURL) ||
		checkStr("ldapBindDn", desired.LdapBindDn) ||
		checkStr("ldapBindPassword", desired.LdapBindPassword) ||
		checkStr("ldapBase", desired.LdapBase) ||
		checkStr("ldapSkipCertVerify", desired.LdapSkipCertVerify) ||
		checkStr("ldapSoftDeleteUsers", desired.LdapSoftDeleteUsers) ||
		checkStr("ldapAdminGroupName", desired.LdapAdminGroupName) ||
		checkStr("ldapUserSearchFilter", desired.LdapUserSearchFilter) ||
		checkStr("ldapUserGroupSearchFilter", desired.LdapUserGroupSearchFilter) ||
		checkStr("ldapAttributeUserUniqueIdentifier", desired.LdapAttributeUserUniqueIdentifier) ||
		checkStr("ldapAttributeUserUsername", desired.LdapAttributeUserUsername) ||
		checkStr("ldapAttributeUserEmail", desired.LdapAttributeUserEmail) ||
		checkStr("ldapAttributeUserFirstName", desired.LdapAttributeUserFirstName) ||
		checkStr("ldapAttributeUserLastName", desired.LdapAttributeUserLastName) ||
		checkStr("ldapAttributeUserDisplayName", desired.LdapAttributeUserDisplayName) ||
		checkStr("ldapAttributeUserProfilePicture", desired.LdapAttributeUserProfilePicture) ||
		checkStr("ldapAttributeGroupMember", desired.LdapAttributeGroupMember) ||
		checkStr("ldapAttributeGroupUniqueIdentifier", desired.LdapAttributeGroupUniqueIdentifier) ||
		checkStr("ldapAttributeGroupName", desired.LdapAttributeGroupName) ||
		check("requireUserEmail", desired.RequireUserEmail)
}

func strPtr(s string) *string {
	return &s
}
