package instance

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
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
		AppName:                          ptr.To(current["appName"]),
		SessionDuration:                  ptr.To(current["sessionDuration"]),
		HomePageURL:                      ptr.To(current["homePageUrl"]),
		DisableAnimations:                ptr.To(current["disableAnimations"]),
		AccentColor:                      current["accentColor"],
		AllowOwnAccountEdit:              ptr.To(current["allowOwnAccountEdit"]),
		AllowUserSignups:                 ptr.To(current["allowUserSignups"]),
		EmailsVerified:                   ptr.To(current["emailsVerified"]),
		SignupDefaultCustomClaims:        current["signupDefaultCustomClaims"],
		SignupDefaultUserGroupIDs:        current["signupDefaultUserGroupIDs"],
		SMTPHost:                         current["smtpHost"],
		SMTPPort:                         current["smtpPort"],
		SMTPFrom:                         current["smtpFrom"],
		SMTPUser:                         current["smtpUser"],
		SMTPPassword:                     current["smtpPassword"],
		SMTPTLS:                          ptr.To(current["smtpTls"]),
		SMTPSkipCertVerify:               current["smtpSkipCertVerify"],
		EmailLoginNotificationEnabled:    ptr.To(current["emailLoginNotificationEnabled"]),
		EmailOneTimeAccessAsAdminEnabled: ptr.To(current["emailOneTimeAccessAsAdminEnabled"]),
		EmailAPIKeyExpirationEnabled:     ptr.To(current["emailApiKeyExpirationEnabled"]),
		EmailOneTimeAccessAsUnauthenticatedEnabled: ptr.To(current["emailOneTimeAccessAsUnauthenticatedEnabled"]),
		EmailVerificationEnabled:                   ptr.To(current["emailVerificationEnabled"]),
		LdapEnabled:                                ptr.To(current["ldapEnabled"]),
		LdapURL:                                    current["ldapUrl"],
		LdapBindDn:                                 current["ldapBindDn"],
		LdapBindPassword:                           current["ldapBindPassword"],
		LdapBase:                                   current["ldapBase"],
		LdapSkipCertVerify:                         current["ldapSkipCertVerify"],
		LdapSoftDeleteUsers:                        current["ldapSoftDeleteUsers"],
		LdapAdminGroupName:                         current["ldapAdminGroupName"],
		LdapUserSearchFilter:                       current["ldapUserSearchFilter"],
		LdapUserGroupSearchFilter:                  current["ldapUserGroupSearchFilter"],
		LdapAttributeUserUniqueIdentifier:          current["ldapAttributeUserUniqueIdentifier"],
		LdapAttributeUserUsername:                  current["ldapAttributeUserUsername"],
		LdapAttributeUserEmail:                     current["ldapAttributeUserEmail"],
		LdapAttributeUserFirstName:                 current["ldapAttributeUserFirstName"],
		LdapAttributeUserLastName:                  current["ldapAttributeUserLastName"],
		LdapAttributeUserDisplayName:               current["ldapAttributeUserDisplayName"],
		LdapAttributeUserProfilePicture:            current["ldapAttributeUserProfilePicture"],
		LdapAttributeGroupMember:                   current["ldapAttributeGroupMember"],
		LdapAttributeGroupUniqueIdentifier:         current["ldapAttributeGroupUniqueIdentifier"],
		LdapAttributeGroupName:                     current["ldapAttributeGroupName"],
		RequireUserEmail:                           ptr.To(current["requireUserEmail"]),
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
		dto.DisableAnimations = ptr.To(fmt.Sprintf("%t", *ui.DisableAnimations))
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
		dto.RequireUserEmail = ptr.To(fmt.Sprintf("%t", *um.RequireUserEmail))
	}
	if um.EmailsVerified != nil {
		dto.EmailsVerified = ptr.To(fmt.Sprintf("%t", *um.EmailsVerified))
	}
	if um.AllowOwnAccountEdit != nil {
		dto.AllowOwnAccountEdit = ptr.To(fmt.Sprintf("%t", *um.AllowOwnAccountEdit))
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
		dto.EmailLoginNotificationEnabled = ptr.To(fmt.Sprintf("%t", *en.LoginNotification))
	}
	if en.OneTimeAccessAsAdmin != nil {
		dto.EmailOneTimeAccessAsAdminEnabled = ptr.To(fmt.Sprintf("%t", *en.OneTimeAccessAsAdmin))
	}
	if en.APIKeyExpiration != nil {
		dto.EmailAPIKeyExpirationEnabled = ptr.To(fmt.Sprintf("%t", *en.APIKeyExpiration))
	}
	if en.OneTimeAccessAsUnauthenticated != nil {
		dto.EmailOneTimeAccessAsUnauthenticatedEnabled = ptr.To(fmt.Sprintf("%t", *en.OneTimeAccessAsUnauthenticated))
	}
	if en.Verification != nil {
		dto.EmailVerificationEnabled = ptr.To(fmt.Sprintf("%t", *en.Verification))
	}
}

func (r *Reconciler) applyLDAPConfig(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, dto *models.GithubComPocketIDPocketIDBackendInternalDtoAppConfigUpdateDto) error {
	if instance.Spec.LDAP == nil {
		return nil
	}
	ldap := instance.Spec.LDAP
	dto.LdapEnabled = ptr.To("true")
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
	ptrFields := []struct {
		key string
		val *string
	}{
		{"appName", desired.AppName},
		{"sessionDuration", desired.SessionDuration},
		{"homePageUrl", desired.HomePageURL},
		{"disableAnimations", desired.DisableAnimations},
		{"allowOwnAccountEdit", desired.AllowOwnAccountEdit},
		{"allowUserSignups", desired.AllowUserSignups},
		{"emailsVerified", desired.EmailsVerified},
		{"smtpTls", desired.SMTPTLS},
		{"emailLoginNotificationEnabled", desired.EmailLoginNotificationEnabled},
		{"emailOneTimeAccessAsAdminEnabled", desired.EmailOneTimeAccessAsAdminEnabled},
		{"emailApiKeyExpirationEnabled", desired.EmailAPIKeyExpirationEnabled},
		{"emailOneTimeAccessAsUnauthenticatedEnabled", desired.EmailOneTimeAccessAsUnauthenticatedEnabled},
		{"emailVerificationEnabled", desired.EmailVerificationEnabled},
		{"ldapEnabled", desired.LdapEnabled},
		{"requireUserEmail", desired.RequireUserEmail},
	}
	for _, f := range ptrFields {
		if f.val != nil && current[f.key] != *f.val {
			return true
		}
	}

	strFields := []struct {
		key string
		val string
	}{
		{"accentColor", desired.AccentColor},
		{"signupDefaultCustomClaims", desired.SignupDefaultCustomClaims},
		{"signupDefaultUserGroupIDs", desired.SignupDefaultUserGroupIDs},
		{"smtpHost", desired.SMTPHost},
		{"smtpPort", desired.SMTPPort},
		{"smtpFrom", desired.SMTPFrom},
		{"smtpUser", desired.SMTPUser},
		{"smtpPassword", desired.SMTPPassword},
		{"smtpSkipCertVerify", desired.SMTPSkipCertVerify},
		{"ldapUrl", desired.LdapURL},
		{"ldapBindDn", desired.LdapBindDn},
		{"ldapBindPassword", desired.LdapBindPassword},
		{"ldapBase", desired.LdapBase},
		{"ldapSkipCertVerify", desired.LdapSkipCertVerify},
		{"ldapSoftDeleteUsers", desired.LdapSoftDeleteUsers},
		{"ldapAdminGroupName", desired.LdapAdminGroupName},
		{"ldapUserSearchFilter", desired.LdapUserSearchFilter},
		{"ldapUserGroupSearchFilter", desired.LdapUserGroupSearchFilter},
		{"ldapAttributeUserUniqueIdentifier", desired.LdapAttributeUserUniqueIdentifier},
		{"ldapAttributeUserUsername", desired.LdapAttributeUserUsername},
		{"ldapAttributeUserEmail", desired.LdapAttributeUserEmail},
		{"ldapAttributeUserFirstName", desired.LdapAttributeUserFirstName},
		{"ldapAttributeUserLastName", desired.LdapAttributeUserLastName},
		{"ldapAttributeUserDisplayName", desired.LdapAttributeUserDisplayName},
		{"ldapAttributeUserProfilePicture", desired.LdapAttributeUserProfilePicture},
		{"ldapAttributeGroupMember", desired.LdapAttributeGroupMember},
		{"ldapAttributeGroupUniqueIdentifier", desired.LdapAttributeGroupUniqueIdentifier},
		{"ldapAttributeGroupName", desired.LdapAttributeGroupName},
	}
	for _, f := range strFields {
		if current[f.key] != f.val {
			return true
		}
	}

	return false
}
