package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// # 로그인 인증 기능
func (s *AuthService) Login(ctx context.Context, login, password, requestIP string) (model.Tokens, error) {
	if err := s.cache.Limit(ctx, "login", requestIP, 20, 15*time.Minute); err != nil {
		return model.Tokens{}, err
	}
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" || len(login) > 254 {
		return model.Tokens{}, model.ErrUnauthorized
	}
	current, err := s.repository.UserByLogin(ctx, login)
	if err != nil {
		return model.Tokens{}, err
	}
	if isBlocked(current) || !current.EmailVerified || !security.IsPasswordValid(password, current.PasswordHash) {
		return model.Tokens{}, model.ErrUnauthorized
	}
	return s.issueTokens(ctx, current)
}

// # 인증 토큰 발급 및 저장 기능
func (s *AuthService) issueTokens(ctx context.Context, current model.User) (model.Tokens, error) {
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

// # Refresh Token 갱신 기능
func (s *AuthService) Refresh(ctx context.Context, raw string) (model.Tokens, error) {
	if raw == "" || len(raw) > 256 {
		return model.Tokens{}, model.ErrUnauthorized
	}
	return s.repository.RotateRefresh(ctx, raw, s.tokens, s.refreshTTL)
}

// # 로그아웃 및 토큰 폐기 기능
func (s *AuthService) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	return s.repository.RevokeToken(ctx, raw)
}

// # Access Token 인증 기능
func (s *AuthService) Authenticate(ctx context.Context, accessToken string) (model.User, error) {
	claims, err := s.tokens.Parse(accessToken)
	if err != nil {
		return model.User{}, err
	}
	current, err := s.repository.UserByID(ctx, claims.Subject)
	if err != nil || isBlocked(current) {
		return model.User{}, model.ErrUnauthorized
	}
	return current, nil
}
