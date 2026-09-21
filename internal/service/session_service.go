package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

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
