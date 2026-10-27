package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/config"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

type OAuthRepository interface {
	UserByID(context.Context, string) (model.User, error)
	UserByOAuth(context.Context, string, string) (model.User, error)
	LinkOAuthAccount(context.Context, string, string, string) error
	CreateOAuthUserWithTerms(context.Context, string, string, string, string, string, []model.Consent) (model.User, error)
	InsertRefresh(context.Context, string, string, string, time.Time) error
}

type OAuthCache interface {
	SaveOAuthState(context.Context, string, redisdb.OAuthState) error
	ConsumeOAuthState(context.Context, string) (redisdb.OAuthState, error)
	SaveOAuthSignup(context.Context, string, redisdb.OAuthSignup) error
	OAuthSignup(context.Context, string) (redisdb.OAuthSignup, error)
	DeleteOAuthSignup(context.Context, string) error
}

type SignupEmailFlow interface {
	StartSignup(context.Context, string, string) (model.SignupStartResult, error)
	SetSignupPassword(context.Context, string, string, string) error
	SendSignupCode(context.Context, string, string) (model.VerificationResult, error)
	VerifySignupCode(context.Context, string, string) error
	Signup(context.Context, string, string) (redisdb.SignupData, error)
	DeleteSignup(context.Context, string) error
}

type OAuthService struct {
	repository OAuthRepository
	cache      OAuthCache
	emailFlow  SignupEmailFlow
	tokens     security.TokenManager
	refreshTTL time.Duration
	apiBaseURL string
	webOrigin  string
	providers  map[string]providerConfig
	client     *http.Client
}

type providerConfig struct {
	name, clientID, clientSecret        string
	authorizeURL, tokenURL, userInfoURL string
	scopes                              []string
	apple                               config.OAuthAppleConfig
}

type oauthIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Nickname      string
	AvatarURL     string
}

func NewOAuthService(repo OAuthRepository, cache OAuthCache, emailFlow SignupEmailFlow, tokens security.TokenManager, refreshTTL time.Duration, cfg config.Config) *OAuthService {
	providers := map[string]providerConfig{
		"google": {name: "GOOGLE", clientID: cfg.OAuth.Google.ClientID, clientSecret: cfg.OAuth.Google.ClientSecret,
			authorizeURL: "https://accounts.google.com/o/oauth2/v2/auth", tokenURL: "https://oauth2.googleapis.com/token",
			userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo", scopes: []string{"openid", "email", "profile"}},
		"kakao": {name: "KAKAO", clientID: cfg.OAuth.Kakao.ClientID, clientSecret: cfg.OAuth.Kakao.ClientSecret,
			authorizeURL: "https://kauth.kakao.com/oauth/authorize", tokenURL: "https://kauth.kakao.com/oauth/token",
			userInfoURL: "https://kapi.kakao.com/v2/user/me", scopes: []string{"account_email", "profile_nickname", "profile_image"}},
		"x": {name: "X", clientID: cfg.OAuth.X.ClientID, clientSecret: cfg.OAuth.X.ClientSecret,
			authorizeURL: "https://x.com/i/oauth2/authorize", tokenURL: "https://api.x.com/2/oauth2/token",
			userInfoURL: "https://api.x.com/2/users/me?user.fields=profile_image_url", scopes: []string{"users.read"}},
		"apple": {name: "APPLE", clientID: cfg.OAuth.Apple.ClientID,
			authorizeURL: "https://appleid.apple.com/auth/authorize", tokenURL: "https://appleid.apple.com/auth/token",
			scopes: []string{"email", "name"}, apple: cfg.OAuth.Apple},
	}
	return &OAuthService{repository: repo, cache: cache, emailFlow: emailFlow, tokens: tokens, refreshTTL: refreshTTL,
		apiBaseURL: cfg.APIBaseURL, webOrigin: cfg.WebOrigin, providers: providers, client: &http.Client{Timeout: 12 * time.Second}}
}

func (s *OAuthService) Begin(ctx context.Context, provider, linkUserID string) (string, error) {
	config, ok := s.providers[strings.ToLower(provider)]
	if !ok || config.clientID == "" {
		return "", model.ErrNotFound
	}
	state, err := security.RandomToken()
	if err != nil {
		return "", err
	}
	value := redisdb.OAuthState{Provider: config.name, UserID: linkUserID}
	if config.name == "X" || config.name == "GOOGLE" {
		value.Verifier, err = security.RandomToken()
		if err != nil {
			return "", err
		}
	}
	if config.name == "APPLE" {
		value.Nonce, err = security.RandomToken()
		if err != nil {
			return "", err
		}
	}
	if err = s.cache.SaveOAuthState(ctx, state, value); err != nil {
		return "", err
	}
	callbackURL := s.apiBaseURL + "/api/v1/auth/oauth/" + strings.ToLower(provider) + "/callback"
	authorizeURL, err := url.Parse(config.authorizeURL)
	if err != nil {
		return "", err
	}
	query := authorizeURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", config.clientID)
	query.Set("redirect_uri", callbackURL)
	query.Set("scope", strings.Join(config.scopes, " "))
	query.Set("state", state)
	if config.name == "APPLE" {
		query.Set("response_mode", "form_post")
		query.Set("nonce", value.Nonce)
	}
	if value.Verifier != "" {
		digest := sha256.Sum256([]byte(value.Verifier))
		query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(digest[:]))
		query.Set("code_challenge_method", "S256")
	}
	authorizeURL.RawQuery = query.Encode()
	return authorizeURL.String(), nil
}

func (s *OAuthService) Callback(ctx context.Context, provider, code, rawState string) (model.OAuthCallbackResult, error) {
	if code == "" || rawState == "" || len(code) > 4096 || len(rawState) > 256 {
		return model.OAuthCallbackResult{}, model.ErrInvalid
	}
	provider = strings.ToLower(provider)
	config, ok := s.providers[provider]
	if !ok || config.clientID == "" {
		return model.OAuthCallbackResult{}, model.ErrNotFound
	}
	state, err := s.cache.ConsumeOAuthState(ctx, rawState)
	if err != nil || state.Provider != config.name {
		return model.OAuthCallbackResult{}, model.ErrUnauthorized
	}
	identity, err := s.exchange(ctx, provider, config, code, state, s.apiBaseURL+"/api/v1/auth/oauth/"+provider+"/callback")
	if err != nil {
		return model.OAuthCallbackResult{}, err
	}
	if state.UserID != "" {
		if err = s.repository.LinkOAuthAccount(ctx, state.UserID, config.name, identity.Subject); err != nil {
			return model.OAuthCallbackResult{}, err
		}
		user, err := s.repository.UserByID(ctx, state.UserID)
		if err != nil || isBlocked(user) {
			return model.OAuthCallbackResult{}, model.ErrUnauthorized
		}
		tokens, err := s.issueTokens(ctx, user)
		if err != nil {
			return model.OAuthCallbackResult{}, err
		}
		return model.OAuthCallbackResult{Tokens: &tokens}, nil
	}
	user, err := s.repository.UserByOAuth(ctx, config.name, identity.Subject)
	if err == nil {
		if isBlocked(user) {
			return model.OAuthCallbackResult{}, model.ErrUnauthorized
		}
		tokens, tokenErr := s.issueTokens(ctx, user)
		if tokenErr != nil {
			return model.OAuthCallbackResult{}, tokenErr
		}
		return model.OAuthCallbackResult{Tokens: &tokens}, nil
	}
	if !errors.Is(err, model.ErrUnauthorized) {
		return model.OAuthCallbackResult{}, err
	}
	sessionID, err := security.RandomToken()
	if err != nil {
		return model.OAuthCallbackResult{}, err
	}
	identity.Email, identity.EmailVerified = normalizeProviderEmail(identity.Email, identity.EmailVerified)
	if !validProviderAvatar(identity.AvatarURL) {
		identity.AvatarURL = ""
	}
	pending := redisdb.OAuthSignup{Provider: config.name, Subject: identity.Subject, Email: identity.Email,
		EmailVerified: identity.EmailVerified, Nickname: identity.Nickname, AvatarURL: identity.AvatarURL}
	if err = s.cache.SaveOAuthSignup(ctx, sessionID, pending); err != nil {
		return model.OAuthCallbackResult{}, err
	}
	return model.OAuthCallbackResult{SignupSessionID: sessionID, EmailRequired: !pending.EmailVerified}, nil
}

func (s *OAuthService) StartEmailVerification(ctx context.Context, oauthSessionID, email, requestIP string) (model.VerificationResult, error) {
	pending, err := s.cache.OAuthSignup(ctx, oauthSessionID)
	if err != nil {
		return model.VerificationResult{}, err
	}
	if pending.EmailVerified {
		return model.VerificationResult{}, model.ErrConflict
	}
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return model.VerificationResult{}, model.ErrInvalid
	}
	if pending.SignupSessionID == "" {
		signup, signupErr := s.emailFlow.StartSignup(ctx, normalized, requestIP)
		if signupErr != nil {
			return model.VerificationResult{}, signupErr
		}
		temporaryPassword, passwordErr := security.RandomToken()
		if passwordErr != nil {
			return model.VerificationResult{}, passwordErr
		}
		if passwordErr = s.emailFlow.SetSignupPassword(ctx, signup.SignupSessionID, temporaryPassword, temporaryPassword); passwordErr != nil {
			return model.VerificationResult{}, passwordErr
		}
		pending.SignupSessionID = signup.SignupSessionID
	}
	if pending.Email != "" && pending.Email != normalized {
		return model.VerificationResult{}, model.ErrConflict
	}
	pending.Email = normalized
	if err = s.cache.SaveOAuthSignup(ctx, oauthSessionID, pending); err != nil {
		return model.VerificationResult{}, err
	}
	return s.emailFlow.SendSignupCode(ctx, pending.SignupSessionID, requestIP)
}

func (s *OAuthService) VerifyEmail(ctx context.Context, oauthSessionID, code string) error {
	pending, err := s.cache.OAuthSignup(ctx, oauthSessionID)
	if err != nil {
		return err
	}
	if pending.SignupSessionID == "" {
		return model.ErrState
	}
	return s.emailFlow.VerifySignupCode(ctx, pending.SignupSessionID, code)
}

func (s *OAuthService) CompleteSignup(ctx context.Context, oauthSessionID, nickname string, consents []model.Consent) (model.Tokens, error) {
	pending, err := s.cache.OAuthSignup(ctx, oauthSessionID)
	if err != nil {
		return model.Tokens{}, err
	}
	email := pending.Email
	if !pending.EmailVerified {
		if pending.SignupSessionID == "" {
			return model.Tokens{}, model.ErrState
		}
		signup, signupErr := s.emailFlow.Signup(ctx, pending.SignupSessionID, "verified")
		if signupErr != nil || signup.Email != pending.Email {
			return model.Tokens{}, model.ErrCode
		}
		email = signup.Email
	}
	email, err = security.NormalizeEmail(email)
	if err != nil {
		return model.Tokens{}, model.ErrInvalid
	}
	nickname = strings.TrimSpace(nickname)
	if nickname == "" {
		nickname = strings.TrimSpace(pending.Nickname)
	}
	if !security.ValidNickname(nickname) {
		nickname = security.NicknameBase(email)
	}
	if !security.ValidNickname(nickname) {
		return model.Tokens{}, model.ErrInvalid
	}
	user, err := s.repository.CreateOAuthUserWithTerms(ctx, pending.Provider, pending.Subject, email, nickname, pending.AvatarURL, consents)
	if err != nil {
		return model.Tokens{}, err
	}
	_ = s.cache.DeleteOAuthSignup(ctx, oauthSessionID)
	if pending.SignupSessionID != "" {
		_ = s.emailFlow.DeleteSignup(ctx, pending.SignupSessionID)
	}
	return s.issueTokens(ctx, user)
}

func (s *OAuthService) issueTokens(ctx context.Context, current model.User) (model.Tokens, error) {
	familyID := uuid.NewString()
	raw, err := security.RandomToken()
	if err != nil {
		return model.Tokens{}, err
	}
	access, err := s.tokens.Issue(current.ID, familyID, current.Role)
	if err != nil {
		return model.Tokens{}, err
	}
	expires := time.Now().Add(s.refreshTTL)
	if err = s.repository.InsertRefresh(ctx, current.ID, familyID, raw, expires); err != nil {
		return model.Tokens{}, err
	}
	return model.Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(s.tokens.TTL.Seconds()), RefreshToken: raw, RefreshExpiresAt: expires, User: current}, nil
}

func (s *OAuthService) exchange(ctx context.Context, provider string, config providerConfig, code string, state redisdb.OAuthState, redirectURI string) (oauthIdentity, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "client_id": {config.clientID}}
	if state.Verifier != "" {
		form.Set("code_verifier", state.Verifier)
	}
	if provider == "apple" {
		secret, err := appleClientSecret(config.apple)
		if err != nil {
			return oauthIdentity{}, err
		}
		form.Set("client_secret", secret)
	} else if provider == "google" || provider == "kakao" {
		form.Set("client_secret", config.clientSecret)
	}
	if provider == "x" && config.clientSecret != "" {
		form.Del("client_id")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthIdentity{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if provider == "x" && config.clientSecret != "" {
		request.SetBasicAuth(config.clientID, config.clientSecret)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	var token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token); err != nil || (token.AccessToken == "" && token.IDToken == "") {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	if provider == "apple" {
		return s.appleIdentity(ctx, token.IDToken, config, state.Nonce)
	}
	return s.userInfo(ctx, provider, config, token.AccessToken)
}

func (s *OAuthService) userInfo(ctx context.Context, provider string, config providerConfig, accessToken string) (oauthIdentity, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.userInfoURL, nil)
	if err != nil {
		return oauthIdentity{}, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	var identity oauthIdentity
	switch provider {
	case "google":
		var data struct {
			Subject       string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
			Picture       string `json:"picture"`
		}
		if err = decodeJSON(response, &data); err != nil {
			return oauthIdentity{}, err
		}
		identity = oauthIdentity{Subject: data.Subject, Email: data.Email, EmailVerified: data.EmailVerified, Nickname: data.Name, AvatarURL: data.Picture}
	case "kakao":
		var data struct {
			ID         json.Number `json:"id"`
			Properties struct {
				Nickname string `json:"nickname"`
				Picture  string `json:"profile_image"`
			} `json:"properties"`
			Account struct {
				Email         string `json:"email"`
				EmailValid    bool   `json:"is_email_valid"`
				EmailVerified bool   `json:"is_email_verified"`
				Profile       struct {
					Nickname string `json:"nickname"`
					Picture  string `json:"profile_image_url"`
				} `json:"profile"`
			} `json:"kakao_account"`
		}
		if err = decodeJSON(response, &data); err != nil {
			return oauthIdentity{}, err
		}
		identity = oauthIdentity{Subject: data.ID.String(), Email: data.Account.Email, EmailVerified: data.Account.EmailValid && data.Account.EmailVerified,
			Nickname: firstNonEmpty(data.Account.Profile.Nickname, data.Properties.Nickname), AvatarURL: firstNonEmpty(data.Account.Profile.Picture, data.Properties.Picture)}
	case "x":
		var data struct {
			Data struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Picture string `json:"profile_image_url"`
			} `json:"data"`
		}
		if err = decodeJSON(response, &data); err != nil {
			return oauthIdentity{}, err
		}
		identity = oauthIdentity{Subject: data.Data.ID, Nickname: data.Data.Name, AvatarURL: data.Data.Picture}
	default:
		return oauthIdentity{}, model.ErrNotFound
	}
	if identity.Subject == "" {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	identity.Email, identity.EmailVerified = normalizeProviderEmail(identity.Email, identity.EmailVerified)
	if !validProviderAvatar(identity.AvatarURL) {
		identity.AvatarURL = ""
	}
	return identity, nil
}

func (s *OAuthService) appleIdentity(ctx context.Context, rawIDToken string, config providerConfig, expectedNonce string) (oauthIdentity, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(rawIDToken, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() || kid == "" {
			return nil, model.ErrUnauthorized
		}
		return applePublicKey(ctx, s.client, kid)
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer("https://appleid.apple.com"), jwt.WithAudience(config.clientID))
	if err != nil || !token.Valid {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	subject, _ := claims["sub"].(string)
	nonce, _ := claims["nonce"].(string)
	email, _ := claims["email"].(string)
	if subject == "" || expectedNonce == "" || nonce != expectedNonce {
		return oauthIdentity{}, model.ErrUnauthorized
	}
	return oauthIdentity{Subject: subject, Email: email, EmailVerified: claimBool(claims["email_verified"])}, nil
}

func decodeJSON(response *http.Response, destination any) error {
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(destination); err != nil {
		return model.ErrUnauthorized
	}
	return nil
}

func normalizeProviderEmail(email string, verified bool) (string, bool) {
	if email == "" {
		return "", false
	}
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return "", false
	}
	return normalized, verified
}

func validProviderAvatar(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func claimBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

func appleClientSecret(config config.OAuthAppleConfig) (string, error) {
	block, _ := pem.Decode(config.PrivateKeyPEM)
	if block == nil {
		return "", errors.New("Apple OAuth private key is invalid")
	}
	var privateKey *ecdsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		privateKey, _ = parsed.(*ecdsa.PrivateKey)
	}
	if privateKey == nil {
		parsed, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", errors.New("Apple OAuth private key is invalid")
		}
		privateKey = parsed
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{Issuer: config.TeamID, Subject: config.ClientID, Audience: jwt.ClaimStrings{"https://appleid.apple.com"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute))}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = config.KeyID
	return token.SignedString(privateKey)
}

type appleJWK struct {
	Keys []struct {
		KID string `json:"kid"`
		KTY string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

var appleKeys = struct {
	sync.RWMutex
	values  map[string]*rsa.PublicKey
	expires time.Time
}{values: map[string]*rsa.PublicKey{}}

func applePublicKey(ctx context.Context, client *http.Client, kid string) (*rsa.PublicKey, error) {
	appleKeys.RLock()
	key := appleKeys.values[kid]
	valid := time.Now().Before(appleKeys.expires)
	appleKeys.RUnlock()
	if key != nil && valid {
		return key, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://appleid.apple.com/auth/keys", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("Apple signing keys unavailable")
	}
	var document appleJWK
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&document); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, item := range document.Keys {
		if item.KTY != "RSA" || item.KID == "" {
			continue
		}
		modulus, decodeErr := base64.RawURLEncoding.DecodeString(item.N)
		if decodeErr != nil {
			continue
		}
		exponentBytes, decodeErr := base64.RawURLEncoding.DecodeString(item.E)
		if decodeErr != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			continue
		}
		exponent := 0
		for _, b := range exponentBytes {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 3 {
			continue
		}
		keys[item.KID] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
	}
	appleKeys.Lock()
	appleKeys.values = keys
	appleKeys.expires = time.Now().Add(time.Hour)
	key = appleKeys.values[kid]
	appleKeys.Unlock()
	if key == nil {
		return nil, model.ErrUnauthorized
	}
	return key, nil
}
