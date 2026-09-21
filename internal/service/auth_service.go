// Package service contains authentication use cases and keeps transport details out of business logic.
package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/cache"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/repository"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

var sixDigitCode = regexp.MustCompile(`^[0-9]{6}$`)

// SignupStartResult is the data needed to render the next signup step.
type SignupStartResult struct {
	SignupSessionID string
	Email           string
	Nickname        string
	ExpiresIn       int64
}

type VerificationResult struct {
	ExpiresIn   int64
	ResendAfter int64
}

type AccountLookupResult struct {
	Email    string
	Username string
}

// SignupCache keeps unfinished signup and reset flows in Redis with TTLs.
type SignupCache interface {
	CreateSignup(context.Context, string, string, string) error
	SetPassword(context.Context, string, string) error
	Signup(context.Context, string, string) (domain.Signup, error)
	DeleteSignup(context.Context, string) error
	SaveCode(context.Context, string, string, string) error
	VerifyCode(context.Context, string, string) error
	Limit(context.Context, string, string, int, time.Duration) error
	SaveReset(context.Context, string, domain.User) error
	ConsumeReset(context.Context, string) (cache.ResetState, error)
}

type AuthService struct {
	repository repository.AuthRepository
	cache      SignupCache
	mailer     mailer.Sender
	tokens     security.TokenManager
	codeKey    []byte
	bcryptCost int
	refreshTTL time.Duration
}

func NewAuthService(repo repository.AuthRepository, ephemeral SignupCache, sender mailer.Sender, tokens security.TokenManager, codeKey []byte, bcryptCost int, refreshTTL time.Duration) *AuthService {
	return &AuthService{
		repository: repo,
		cache:      ephemeral,
		mailer:     sender,
		tokens:     tokens,
		codeKey:    codeKey,
		bcryptCost: bcryptCost,
		refreshTTL: refreshTTL,
	}
}

func (s *AuthService) Terms(ctx context.Context) ([]domain.Term, error) {
	return s.repository.Terms(ctx)
}

func (s *AuthService) StartSignup(ctx context.Context, email, requestIP string) (SignupStartResult, error) {
	if err := s.cache.Limit(ctx, "signup-start", requestIP, 10, time.Hour); err != nil {
		return SignupStartResult{}, err
	}
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return SignupStartResult{}, err
	}
	exists, err := s.repository.EmailExists(ctx, normalized)
	if err != nil {
		return SignupStartResult{}, err
	}
	if exists {
		return SignupStartResult{}, domain.ErrConflict
	}

	nickname := security.NicknameBase(normalized)
	if !security.ValidNickname(nickname) {
		return SignupStartResult{}, domain.ErrInvalid
	}
	sessionID := uuid.NewString()
	if err := s.cache.CreateSignup(ctx, sessionID, normalized, nickname); err != nil {
		return SignupStartResult{}, err
	}
	return SignupStartResult{SignupSessionID: sessionID, Email: normalized, Nickname: nickname, ExpiresIn: int64(cache.SignupTTL.Seconds())}, nil
}

func (s *AuthService) SetSignupPassword(ctx context.Context, sessionID, password, confirmation string) error {
	if password != confirmation {
		return domain.ErrInvalid
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return domain.ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	return s.cache.SetPassword(ctx, sessionID, hash)
}

func (s *AuthService) SendSignupCode(ctx context.Context, sessionID, requestIP string) (VerificationResult, error) {
	signup, err := s.cache.Signup(ctx, sessionID, "password")
	if err != nil {
		return VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send", signup.Email, 5, time.Hour); err != nil {
		return VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send-ip", requestIP, 20, time.Hour); err != nil {
		return VerificationResult{}, err
	}
	code, err := security.NewCode()
	if err != nil {
		return VerificationResult{}, err
	}
	if err = s.cache.SaveCode(ctx, sessionID, signup.Email, security.CodeHash(s.codeKey, sessionID, code)); err != nil {
		return VerificationResult{}, err
	}
	if err = s.mailer.Verification(signup.Email, code); err != nil {
		return VerificationResult{}, errors.New("메일을 발송하지 못했습니다")
	}
	return VerificationResult{ExpiresIn: int64(cache.CodeTTL.Seconds()), ResendAfter: 60}, nil
}

func (s *AuthService) VerifySignupCode(ctx context.Context, sessionID, code string) error {
	if !sixDigitCode.MatchString(code) {
		return domain.ErrCode
	}
	return s.cache.VerifyCode(ctx, sessionID, security.CodeHash(s.codeKey, sessionID, code))
}

func (s *AuthService) CompleteSignup(ctx context.Context, sessionID string, consents []domain.Consent) (domain.Tokens, error) {
	signup, err := s.cache.Signup(ctx, sessionID, "verified")
	if err != nil {
		return domain.Tokens{}, err
	}
	user, err := s.repository.CreateUserWithTerms(ctx, signup, consents)
	if err != nil {
		return domain.Tokens{}, err
	}
	// 영속 회원 생성 후 임시 상태는 제거합니다. 삭제 실패가 이미 완료된 가입을 되돌리지는 않습니다.
	_ = s.cache.DeleteSignup(ctx, sessionID)
	return s.issueTokens(ctx, user)
}

func (s *AuthService) Login(ctx context.Context, login, password, requestIP string) (domain.Tokens, error) {
	if err := s.cache.Limit(ctx, "login", requestIP, 20, 15*time.Minute); err != nil {
		return domain.Tokens{}, err
	}
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" || len(login) > 254 {
		return domain.Tokens{}, domain.ErrUnauthorized
	}
	user, err := s.repository.UserByLogin(ctx, login)
	if err != nil {
		return domain.Tokens{}, err
	}
	if isBlocked(user) || !user.EmailVerified || !security.IsPasswordValid(password, user.PasswordHash) {
		return domain.Tokens{}, domain.ErrUnauthorized
	}
	return s.issueTokens(ctx, user)
}

func (s *AuthService) issueTokens(ctx context.Context, user domain.User) (domain.Tokens, error) {
	familyID := uuid.NewString()
	raw, err := security.RandomToken()
	if err != nil {
		return domain.Tokens{}, err
	}
	access, err := s.tokens.Issue(user.ID, familyID, user.Role)
	if err != nil {
		return domain.Tokens{}, err
	}
	expires := time.Now().Add(s.refreshTTL)
	if err = s.repository.InsertRefresh(ctx, user.ID, familyID, raw, expires); err != nil {
		return domain.Tokens{}, err
	}
	return domain.Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(s.tokens.TTL.Seconds()), RefreshToken: raw, RefreshExpiresAt: expires, User: user}, nil
}

func (s *AuthService) Refresh(ctx context.Context, raw string) (domain.Tokens, error) {
	if raw == "" || len(raw) > 256 {
		return domain.Tokens{}, domain.ErrUnauthorized
	}
	return s.repository.RotateRefresh(ctx, raw, s.tokens, s.refreshTTL)
}

func (s *AuthService) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	return s.repository.RevokeToken(ctx, raw)
}

func (s *AuthService) Authenticate(ctx context.Context, accessToken string) (domain.User, error) {
	claims, err := s.tokens.Parse(accessToken)
	if err != nil {
		return domain.User{}, err
	}
	user, err := s.repository.UserByID(ctx, claims.Subject)
	if err != nil || isBlocked(user) {
		return domain.User{}, domain.ErrUnauthorized
	}
	return user, nil
}

func (s *AuthService) UpdateNickname(ctx context.Context, userID, nickname string) (domain.User, error) {
	if !security.ValidNickname(nickname) {
		return domain.User{}, domain.ErrInvalid
	}
	if err := s.repository.UpdateNickname(ctx, userID, nickname); err != nil {
		return domain.User{}, err
	}
	return s.repository.UserByID(ctx, userID)
}

func (s *AuthService) ForgotPassword(ctx context.Context, email, requestIP string) error {
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return nil
	}
	if err = s.cache.Limit(ctx, "password-forgot", requestIP, 5, time.Hour); err != nil {
		return err
	}
	user, err := s.repository.UserByEmail(ctx, normalized)
	if errors.Is(err, domain.ErrUnauthorized) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := security.RandomToken()
	if err != nil {
		return err
	}
	if err = s.cache.SaveReset(ctx, raw, user); err != nil {
		return err
	}
	if err = s.mailer.PasswordReset(user.Email, raw); err != nil {
		return errors.New("메일을 발송하지 못했습니다")
	}
	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, rawToken, password, confirmation string) error {
	if password != confirmation || len(rawToken) > 256 {
		return domain.ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	reset, err := s.cache.ConsumeReset(ctx, rawToken)
	if err != nil {
		return domain.ErrUnauthorized
	}
	user, err := s.repository.UserByID(ctx, reset.UserID)
	if err != nil || user.PasswordVersion != reset.PasswordVersion {
		return domain.ErrUnauthorized
	}
	return s.repository.ResetPassword(ctx, user.ID, hash)
}

func (s *AuthService) FindAccount(ctx context.Context, login string) (AccountLookupResult, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	var user domain.User
	var err error
	if strings.Contains(login, "@") {
		login, err = security.NormalizeEmail(login)
		if err != nil {
			return AccountLookupResult{}, domain.ErrUnauthorized
		}
		user, err = s.repository.UserByEmail(ctx, login)
	} else {
		user, err = s.repository.UserByLogin(ctx, login)
	}
	if err != nil {
		return AccountLookupResult{}, err
	}
	return AccountLookupResult{Email: domain.MaskEmail(user.Email), Username: user.Username}, nil
}

func isBlocked(user domain.User) bool {
	return strings.EqualFold(user.Status, "BLOCKED")
}
