// Package pocketid provides a clean wrapper around the Pocket-ID API client.
package pocketid

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	apiclient "github.com/aclerici38/pocket-id-go-client/v2/client"
	"github.com/aclerici38/pocket-id-go-client/v2/client/api_keys"
	custom_claims "github.com/aclerici38/pocket-id-go-client/v2/client/custom_claims"
	oidc "github.com/aclerici38/pocket-id-go-client/v2/client/o_id_c"
	"github.com/aclerici38/pocket-id-go-client/v2/client/user_groups"
	"github.com/aclerici38/pocket-id-go-client/v2/client/users"
	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

// Client wraps the Pocket-ID API client with a cleaner interface.
type Client struct {
	raw        *apiclient.PocketIDAPI
	transport  *httptransport.Runtime
	baseURL    string
	httpClient *http.Client
}

// User represents a Pocket-ID user with clean field names.
type User struct {
	ID          string
	Username    string
	FirstName   string
	LastName    string
	Email       string
	DisplayName string
	IsAdmin     bool
	Disabled    bool
	Locale      string
}

// APIKey represents a Pocket-ID API key.
type APIKey struct {
	ID          string
	Name        string
	Description string
	CreatedAt   string
	ExpiresAt   string
	LastUsedAt  string
}

// APIKeyWithToken is returned when creating an API key (token only available once).
type APIKeyWithToken struct {
	APIKey
	Token string
}

// OIDCClient represents an OIDC client with key configuration.
type OIDCClient struct {
	ID                       string
	Name                     string
	CallbackURLs             []string
	LogoutCallbackURLs       []string
	LaunchURL                string
	LogoURL                  string
	DarkLogoURL              string
	HasLogo                  bool
	HasDarkLogo              bool
	IsPublic                 bool
	IsGroupRestricted        bool
	PKCEEnabled              bool
	RequiresReauthentication bool
	AllowedUserGroupIDs      []string
}

// OIDCClientFederatedIdentity represents a federated identity for OIDC clients.
type OIDCClientFederatedIdentity struct {
	Issuer   string
	Subject  string
	Audience string
	JWKS     string
}

// OIDCClientCredentials holds optional federated identity configuration.
type OIDCClientCredentials struct {
	FederatedIdentities []OIDCClientFederatedIdentity
}

// OIDCClientInput contains fields for creating or updating an OIDC client.
type OIDCClientInput struct {
	ID                       string
	Name                     string
	CallbackURLs             []string
	LogoutCallbackURLs       []string
	LaunchURL                string
	LogoURL                  string
	DarkLogoURL              string
	HasLogo                  bool
	HasDarkLogo              bool
	IsPublic                 bool
	IsGroupRestricted        bool
	PKCEEnabled              bool
	RequiresReauthentication bool
	Credentials              *OIDCClientCredentials
}

// CustomClaim represents a custom claim key/value pair.
type CustomClaim struct {
	Key   string
	Value string
}

// UserGroup represents a Pocket-ID user group.
type UserGroup struct {
	ID           string
	Name         string
	FriendlyName string
	CreatedAt    string
	LdapID       string
	UserCount    int
	CustomClaims []CustomClaim
}

// NewClient creates a new Pocket-ID client for the given base URL.
func NewClient(baseURL string) *Client {
	parsed, _ := url.Parse(baseURL)
	transport := httptransport.New(parsed.Host, "/", []string{parsed.Scheme})
	raw := apiclient.New(transport, strfmt.Default)

	return &Client{
		raw:        raw,
		transport:  transport,
		baseURL:    parsed.Scheme + "://" + parsed.Host,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// WithAPIKey returns a new client authenticated with an API key.
func (c *Client) WithAPIKey(apiKey string) *Client {
	newTransport := c.transport
	newTransport.DefaultAuthentication = runtime.ClientAuthInfoWriterFunc(
		func(req runtime.ClientRequest, reg strfmt.Registry) error {
			return req.SetHeaderParam("X-API-KEY", apiKey)
		},
	)

	return &Client{
		raw:        apiclient.New(newTransport, strfmt.Default),
		transport:  newTransport,
		baseURL:    c.baseURL,
		httpClient: c.httpClient,
	}
}

// WithCookie returns a new client authenticated with a session cookie.
func (c *Client) WithCookie(cookie *http.Cookie) *Client {
	newTransport := c.transport
	newTransport.DefaultAuthentication = runtime.ClientAuthInfoWriterFunc(
		func(req runtime.ClientRequest, reg strfmt.Registry) error {
			return req.SetHeaderParam("Cookie", cookie.String())
		},
	)

	return &Client{
		raw:        apiclient.New(newTransport, strfmt.Default),
		transport:  newTransport,
		baseURL:    c.baseURL,
		httpClient: c.httpClient,
	}
}

// --- User Operations ---

// Setup creates the initial admin user on a fresh Pocket-ID instance.
// This only works if no users exist yet.
// Returns the created user and a session cookie for subsequent authenticated requests.
func (c *Client) Setup(ctx context.Context, username, firstName, lastName, email string) (*User, *http.Cookie, error) {
	params := users.NewPostAPISignupSetupParams().
		WithContext(ctx).
		WithBody(&models.GithubComPocketIDPocketIDBackendInternalDtoSignUpDto{
			Username:  &username,
			FirstName: &firstName,
			LastName:  lastName,
			Email:     email,
		})

	resp, err := c.raw.Users.PostAPISignupSetup(params)
	if err != nil {
		return nil, nil, fmt.Errorf("setup failed: %w", err)
	}

	user := userFromDTO(resp.Payload)

	// Cookie extracted in bootstrap.go
	return user, nil, nil
}

func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	params := users.NewGetAPIUsersIDParams().
		WithContext(ctx).
		WithID(id)

	resp, err := c.raw.Users.GetAPIUsersID(params)
	if err != nil {
		return nil, fmt.Errorf("get user failed: %w", err)
	}

	return userFromDTO(resp.Payload), nil
}

func (c *Client) GetCurrentUser(ctx context.Context) (*User, error) {
	params := users.NewGetAPIUsersMeParams().WithContext(ctx)

	resp, err := c.raw.Users.GetAPIUsersMe(params)
	if err != nil {
		return nil, fmt.Errorf("get current user failed: %w", err)
	}

	return userFromDTO(resp.Payload), nil
}

// UserInput contains the fields for creating or updating a user.
type UserInput struct {
	Username    string
	FirstName   string
	LastName    string
	Email       string
	DisplayName string
	IsAdmin     bool
	Disabled    bool
	Locale      string
}

func (c *Client) CreateUser(ctx context.Context, input UserInput) (*User, error) {
	params := users.NewPostAPIUsersParams().
		WithContext(ctx).
		WithUser(&models.GithubComPocketIDPocketIDBackendInternalDtoUserCreateDto{
			Username:    &input.Username,
			FirstName:   &input.FirstName,
			LastName:    input.LastName,
			Email:       input.Email,
			DisplayName: &input.DisplayName,
			IsAdmin:     input.IsAdmin,
			Disabled:    input.Disabled,
			Locale:      input.Locale,
		})

	resp, err := c.raw.Users.PostAPIUsers(params)
	if err != nil {
		return nil, fmt.Errorf("create user failed: %w", err)
	}

	return userFromDTO(resp.Payload), nil
}

// UpdateUser updates an existing user.
func (c *Client) UpdateUser(ctx context.Context, id string, input UserInput) (*User, error) {
	params := users.NewPutAPIUsersIDParams().
		WithContext(ctx).
		WithID(id).
		WithUser(&models.GithubComPocketIDPocketIDBackendInternalDtoUserCreateDto{
			Username:    &input.Username,
			FirstName:   &input.FirstName,
			LastName:    input.LastName,
			Email:       input.Email,
			DisplayName: &input.DisplayName,
			IsAdmin:     input.IsAdmin,
			Disabled:    input.Disabled,
			Locale:      input.Locale,
		})

	resp, err := c.raw.Users.PutAPIUsersID(params)
	if err != nil {
		return nil, fmt.Errorf("update user failed: %w", err)
	}

	return userFromDTO(resp.Payload), nil
}

func (c *Client) DeleteUser(ctx context.Context, id string) error {
	params := users.NewDeleteAPIUsersIDParams().
		WithContext(ctx).
		WithID(id)

	_, err := c.raw.Users.DeleteAPIUsersID(params)
	if err != nil {
		return fmt.Errorf("delete user failed: %w", err)
	}

	return nil
}

// --- API Key Operations ---

func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	params := api_keys.NewGetAPIAPIKeysParams().WithContext(ctx)

	resp, err := c.raw.APIKeys.GetAPIAPIKeys(params)
	if err != nil {
		return nil, fmt.Errorf("list API keys failed: %w", err)
	}

	keys := make([]APIKey, 0, len(resp.Payload.Data))
	for _, k := range resp.Payload.Data {
		keys = append(keys, apiKeyFromDTO(k))
	}

	return keys, nil
}

// CreateAPIKey creates a new API key. The token is only returned once.
func (c *Client) CreateAPIKey(ctx context.Context, name, expiresAt, description string) (*APIKeyWithToken, error) {
	params := api_keys.NewPostAPIAPIKeysParams().
		WithContext(ctx).
		WithAPIKey(&models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyCreateDto{
			Name:        &name,
			ExpiresAt:   &expiresAt,
			Description: description,
		})

	resp, err := c.raw.APIKeys.PostAPIAPIKeys(params)
	if err != nil {
		return nil, fmt.Errorf("create API key failed: %w", err)
	}

	return &APIKeyWithToken{
		APIKey: apiKeyFromDTO(resp.Payload.APIKey),
		Token:  resp.Payload.Token,
	}, nil
}

// CreateAPIKeyForUser creates an API key for the specified user by exchanging a one-time access token for a session.
func (c *Client) CreateAPIKeyForUser(ctx context.Context, userID, name, expiresAt, description string, tokenTTLMinutes int) (*APIKeyWithToken, error) {
	token, err := c.CreateOneTimeAccessToken(ctx, userID, tokenTTLMinutes)
	if err != nil {
		return nil, fmt.Errorf("create one-time access token: %w", err)
	}

	session := newSessionClient(c.baseURL, c.httpClient)
	cookies, err := session.exchangeOneTimeAccessToken(ctx, token.Token)
	if err != nil {
		return nil, fmt.Errorf("exchange one-time access token: %w", err)
	}

	apiKeyReq := CreateAPIKeyRequest{
		Name:        name,
		ExpiresAt:   expiresAt,
		Description: description,
	}
	apiKeyResp, err := session.createAPIKeyWithCookies(ctx, cookies, apiKeyReq)
	if err != nil {
		return nil, fmt.Errorf("create API key: %w", err)
	}

	return &APIKeyWithToken{
		APIKey: apiKeyFromCreateResponse(apiKeyResp),
		Token:  apiKeyResp.Token,
	}, nil
}

// DeleteAPIKey deletes an API key by ID.
func (c *Client) DeleteAPIKey(ctx context.Context, id string) error {
	params := api_keys.NewDeleteAPIAPIKeysIDParams().
		WithContext(ctx).
		WithID(id)

	_, err := c.raw.APIKeys.DeleteAPIAPIKeysID(params)
	if err != nil {
		return fmt.Errorf("delete API key failed: %w", err)
	}

	return nil
}

// --- OIDC Client Operations ---

func (c *Client) CreateOIDCClient(ctx context.Context, input OIDCClientInput) (*OIDCClient, error) {
	params := oidc.NewPostAPIOidcClientsParams().
		WithContext(ctx).
		WithClient(&models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientCreateDto{
			ID:                       input.ID,
			Name:                     &input.Name,
			CallbackURLs:             input.CallbackURLs,
			LogoutCallbackURLs:       input.LogoutCallbackURLs,
			LaunchURL:                input.LaunchURL,
			LogoURL:                  input.LogoURL,
			DarkLogoURL:              input.DarkLogoURL,
			HasLogo:                  input.HasLogo,
			HasDarkLogo:              input.HasDarkLogo,
			IsPublic:                 input.IsPublic,
			IsGroupRestricted:        input.IsGroupRestricted,
			PkceEnabled:              input.PKCEEnabled,
			RequiresReauthentication: input.RequiresReauthentication,
			Credentials:              oidcCredentialsToDTO(input.Credentials),
		})

	resp, err := c.raw.OIDc.PostAPIOidcClients(params)
	if err != nil {
		return nil, fmt.Errorf("create OIDC client failed: %w", err)
	}

	return oidcClientFromAllowedGroupsDTO(resp.Payload), nil
}

func (c *Client) UpdateOIDCClient(ctx context.Context, id string, input OIDCClientInput) (*OIDCClient, error) {
	params := oidc.NewPutAPIOidcClientsIDParams().
		WithContext(ctx).
		WithID(id).
		WithClient(&models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientUpdateDto{
			Name:                     &input.Name,
			CallbackURLs:             input.CallbackURLs,
			LogoutCallbackURLs:       input.LogoutCallbackURLs,
			LaunchURL:                input.LaunchURL,
			LogoURL:                  input.LogoURL,
			DarkLogoURL:              input.DarkLogoURL,
			HasLogo:                  input.HasLogo,
			HasDarkLogo:              input.HasDarkLogo,
			IsPublic:                 input.IsPublic,
			IsGroupRestricted:        input.IsGroupRestricted,
			PkceEnabled:              input.PKCEEnabled,
			RequiresReauthentication: input.RequiresReauthentication,
			Credentials:              oidcCredentialsToDTO(input.Credentials),
		})

	resp, err := c.raw.OIDc.PutAPIOidcClientsID(params)
	if err != nil {
		return nil, fmt.Errorf("update OIDC client failed: %w", err)
	}

	return oidcClientFromAllowedGroupsDTO(resp.Payload), nil
}

func (c *Client) GetOIDCClient(ctx context.Context, id string) (*OIDCClient, error) {
	params := oidc.NewGetAPIOidcClientsIDParams().
		WithContext(ctx).
		WithID(id)

	resp, err := c.raw.OIDc.GetAPIOidcClientsID(params)
	if err != nil {
		return nil, fmt.Errorf("get OIDC client failed: %w", err)
	}

	return oidcClientFromAllowedGroupsDTO(resp.Payload), nil
}

func (c *Client) DeleteOIDCClient(ctx context.Context, id string) error {
	params := oidc.NewDeleteAPIOidcClientsIDParams().
		WithContext(ctx).
		WithID(id)

	_, err := c.raw.OIDc.DeleteAPIOidcClientsID(params)
	if err != nil {
		return fmt.Errorf("delete OIDC client failed: %w", err)
	}

	return nil
}

func (c *Client) UpdateOIDCClientAllowedGroups(ctx context.Context, id string, groupIDs []string) error {
	params := oidc.NewPutAPIOidcClientsIDAllowedUserGroupsParams().
		WithContext(ctx).
		WithID(id).
		WithGroups(&models.GithubComPocketIDPocketIDBackendInternalDtoOidcUpdateAllowedUserGroupsDto{
			UserGroupIds: groupIDs,
		})

	if _, err := c.raw.OIDc.PutAPIOidcClientsIDAllowedUserGroups(params); err != nil {
		return fmt.Errorf("update OIDC client allowed groups failed: %w", err)
	}

	return nil
}

// RegenerateOIDCClientSecret regenerates the client secret and returns it.
// This is the only way to retrieve the client secret from Pocket ID.
// The secret is only returned once and cannot be retrieved later without re-generating
func (c *Client) RegenerateOIDCClientSecret(ctx context.Context, id string) (string, error) {
	params := oidc.NewPostAPIOidcClientsIDSecretParams().
		WithContext(ctx).
		WithID(id)

	resp, err := c.raw.OIDc.PostAPIOidcClientsIDSecret(params)
	if err != nil {
		return "", fmt.Errorf("regenerate OIDC client secret failed: %w", err)
	}

	// The response payload is `any` type, so we need to type assert
	payload, ok := resp.GetPayload().(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response format")
	}

	secret, ok := payload["secret"].(string)
	if !ok {
		return "", fmt.Errorf("secret not found in response")
	}

	return secret, nil
}

// --- User Group Operations ---

func (c *Client) CreateUserGroup(ctx context.Context, name, friendlyName string) (*UserGroup, error) {
	params := user_groups.NewPostAPIUserGroupsParams().
		WithContext(ctx).
		WithUserGroup(&models.GithubComPocketIDPocketIDBackendInternalDtoUserGroupCreateDto{
			Name:         &name,
			FriendlyName: &friendlyName,
		})

	resp, err := c.raw.UserGroups.PostAPIUserGroups(params)
	if err != nil {
		return nil, fmt.Errorf("create user group failed: %w", err)
	}

	return userGroupFromDTO(resp.Payload), nil
}

func (c *Client) UpdateUserGroup(ctx context.Context, id, name, friendlyName string) (*UserGroup, error) {
	params := user_groups.NewPutAPIUserGroupsIDParams().
		WithContext(ctx).
		WithID(id).
		WithUserGroup(&models.GithubComPocketIDPocketIDBackendInternalDtoUserGroupCreateDto{
			Name:         &name,
			FriendlyName: &friendlyName,
		})

	resp, err := c.raw.UserGroups.PutAPIUserGroupsID(params)
	if err != nil {
		return nil, fmt.Errorf("update user group failed: %w", err)
	}

	return userGroupFromDTO(resp.Payload), nil
}

func (c *Client) GetUserGroup(ctx context.Context, id string) (*UserGroup, error) {
	params := user_groups.NewGetAPIUserGroupsIDParams().
		WithContext(ctx).
		WithID(id)

	resp, err := c.raw.UserGroups.GetAPIUserGroupsID(params)
	if err != nil {
		return nil, fmt.Errorf("get user group failed: %w", err)
	}

	return userGroupFromDTO(resp.Payload), nil
}

func (c *Client) DeleteUserGroup(ctx context.Context, id string) error {
	params := user_groups.NewDeleteAPIUserGroupsIDParams().
		WithContext(ctx).
		WithID(id)

	if _, err := c.raw.UserGroups.DeleteAPIUserGroupsID(params); err != nil {
		return fmt.Errorf("delete user group failed: %w", err)
	}

	return nil
}

func (c *Client) UpdateUserGroupUsers(ctx context.Context, id string, userIDs []string) error {
	params := user_groups.NewPutAPIUserGroupsIDUsersParams().
		WithContext(ctx).
		WithID(id).
		WithUsers(&models.GithubComPocketIDPocketIDBackendInternalDtoUserGroupUpdateUsersDto{
			UserIds: userIDs,
		})

	if _, err := c.raw.UserGroups.PutAPIUserGroupsIDUsers(params); err != nil {
		return fmt.Errorf("update user group users failed: %w", err)
	}

	return nil
}

func (c *Client) UpdateUserGroupCustomClaims(ctx context.Context, id string, claims []CustomClaim) ([]CustomClaim, error) {
	payload := make([]*models.GithubComPocketIDPocketIDBackendInternalDtoCustomClaimCreateDto, 0, len(claims))
	for _, claim := range claims {
		key := claim.Key
		value := claim.Value
		payload = append(payload, &models.GithubComPocketIDPocketIDBackendInternalDtoCustomClaimCreateDto{
			Key:   &key,
			Value: &value,
		})
	}

	params := custom_claims.NewPutAPICustomClaimsUserGroupUserGroupIDParams().
		WithContext(ctx).
		WithUserGroupID(id).
		WithClaims(payload)

	resp, err := c.raw.CustomClaims.PutAPICustomClaimsUserGroupUserGroupID(params)
	if err != nil {
		return nil, fmt.Errorf("update user group custom claims failed: %w", err)
	}

	return customClaimsFromDTO(resp.Payload), nil
}

// --- One-Time Access Token Operations ---

// OneTimeAccessToken represents a one-time login token.
type OneTimeAccessToken struct {
	Token string
}

// CreateOneTimeAccessToken creates a one-time access token for a user.
// This token can be used to log in via the browser at /lc/{token}
func (c *Client) CreateOneTimeAccessToken(ctx context.Context, userID string, expiresInMinutes int) (*OneTimeAccessToken, error) {
	params := users.NewPostAPIUsersIDOneTimeAccessTokenParams().
		WithContext(ctx).
		WithID(userID).
		WithBody(map[string]interface{}{
			"userId": userID,
			"ttl":    fmt.Sprintf("%dm", expiresInMinutes),
		})

	resp, err := c.raw.Users.PostAPIUsersIDOneTimeAccessToken(params)
	if err != nil {
		return nil, fmt.Errorf("create one-time access token failed: %w", err)
	}

	// The response payload is `any` type, so we need to type assert
	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	token, ok := payload["token"].(string)
	if !ok {
		return nil, fmt.Errorf("token not found in response")
	}

	return &OneTimeAccessToken{Token: token}, nil
}

// --- Helpers ---

func userFromDTO(dto *models.GithubComPocketIDPocketIDBackendInternalDtoUserDto) *User {
	if dto == nil {
		return nil
	}
	return &User{
		ID:          dto.ID,
		Username:    dto.Username,
		FirstName:   dto.FirstName,
		LastName:    dto.LastName,
		Email:       dto.Email,
		DisplayName: dto.DisplayName,
		IsAdmin:     dto.IsAdmin,
		Disabled:    dto.Disabled,
		Locale:      dto.Locale,
	}
}

func apiKeyFromDTO(dto *models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto) APIKey {
	if dto == nil {
		return APIKey{}
	}
	return APIKey{
		ID:          dto.ID,
		Name:        dto.Name,
		Description: dto.Description,
		CreatedAt:   dto.CreatedAt,
		ExpiresAt:   dto.ExpiresAt,
		LastUsedAt:  dto.LastUsedAt,
	}
}

func apiKeyFromCreateResponse(resp *CreateAPIKeyResponse) APIKey {
	if resp == nil {
		return APIKey{}
	}
	return APIKey{
		ID:          resp.APIKey.ID,
		Name:        resp.APIKey.Name,
		Description: resp.APIKey.Description,
		CreatedAt:   resp.APIKey.CreatedAt,
		ExpiresAt:   resp.APIKey.ExpiresAt,
	}
}

func oidcCredentialsToDTO(credentials *OIDCClientCredentials) *models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientCredentialsDto {
	if credentials == nil {
		return nil
	}
	identities := make([]*models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientFederatedIdentityDto, 0, len(credentials.FederatedIdentities))
	for _, identity := range credentials.FederatedIdentities {
		identities = append(identities, &models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientFederatedIdentityDto{
			Issuer:   identity.Issuer,
			Subject:  identity.Subject,
			Audience: identity.Audience,
			Jwks:     identity.JWKS,
		})
	}
	return &models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientCredentialsDto{
		FederatedIdentities: identities,
	}
}

func oidcClientFromAllowedGroupsDTO(dto *models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientWithAllowedUserGroupsDto) *OIDCClient {
	if dto == nil {
		return nil
	}
	groupIDs := make([]string, 0, len(dto.AllowedUserGroups))
	for _, group := range dto.AllowedUserGroups {
		if group == nil || group.ID == "" {
			continue
		}
		groupIDs = append(groupIDs, group.ID)
	}
	return &OIDCClient{
		ID:                       dto.ID,
		Name:                     dto.Name,
		CallbackURLs:             dto.CallbackURLs,
		LogoutCallbackURLs:       dto.LogoutCallbackURLs,
		LaunchURL:                dto.LaunchURL,
		LogoURL:                  "",
		DarkLogoURL:              "",
		HasLogo:                  dto.HasLogo,
		HasDarkLogo:              dto.HasDarkLogo,
		IsPublic:                 dto.IsPublic,
		IsGroupRestricted:        dto.IsGroupRestricted,
		PKCEEnabled:              dto.PkceEnabled,
		RequiresReauthentication: dto.RequiresReauthentication,
		AllowedUserGroupIDs:      groupIDs,
	}
}

func userGroupFromDTO(dto *models.GithubComPocketIDPocketIDBackendInternalDtoUserGroupDto) *UserGroup {
	if dto == nil {
		return nil
	}
	return &UserGroup{
		ID:           dto.ID,
		Name:         dto.Name,
		FriendlyName: dto.FriendlyName,
		CreatedAt:    dto.CreatedAt,
		LdapID:       dto.LdapID,
		UserCount:    len(dto.Users),
		CustomClaims: customClaimsFromDTO(dto.CustomClaims),
	}
}

func customClaimsFromDTO(dto []*models.GithubComPocketIDPocketIDBackendInternalDtoCustomClaimDto) []CustomClaim {
	if len(dto) == 0 {
		return nil
	}
	claims := make([]CustomClaim, 0, len(dto))
	for _, claim := range dto {
		if claim == nil {
			continue
		}
		claims = append(claims, CustomClaim{
			Key:   claim.Key,
			Value: claim.Value,
		})
	}
	if len(claims) == 0 {
		return nil
	}
	return claims
}
