package auth

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/user"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

func (s *AuthService) Login(ctx context.Context, login, password, requestIP string) (Tokens, error) {
	if err := s.cache.Limit(ctx, "login", requestIP, 20, 15*time.Minute); err != nil {
		return Tokens{}, err
	}
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" || len(login) > 254 {
		return Tokens{}, ErrUnauthorized
	}
	current, err := s.repository.UserByLogin(ctx, login)
	if err != nil {
		return Tokens{}, err
	}
	if isBlocked(current) || !current.EmailVerified || !security.IsPasswordValid(password, current.PasswordHash) {
		return Tokens{}, ErrUnauthorized
	}
	return s.issueTokens(ctx, current)
}

func (s *AuthService) issueTokens(ctx context.Context, current user.User) (Tokens, error) {
	familyID := uuid.NewString()
	raw, err := security.RandomToken()
	if err != nil {
		return Tokens{}, err
	}
	access, err := s.tokens.Issue(current.ID, familyID, current.Role)
	if err != nil {
		return Tokens{}, err
	}
	expires := time.Now().Add(s.refreshTTL)
	if err = s.repository.InsertRefresh(ctx, current.ID, familyID, raw, expires); err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(s.tokens.TTL.Seconds()), RefreshToken: raw, RefreshExpiresAt: expires, User: current}, nil
}

func (s *AuthService) Refresh(ctx context.Context, raw string) (Tokens, error) {
	if raw == "" || len(raw) > 256 {
		return Tokens{}, ErrUnauthorized
	}
	return s.repository.RotateRefresh(ctx, raw, s.tokens, s.refreshTTL)
}

func (s *AuthService) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	return s.repository.RevokeToken(ctx, raw)
}

func (s *AuthService) Authenticate(ctx context.Context, accessToken string) (user.User, error) {
	claims, err := s.tokens.Parse(accessToken)
	if err != nil {
		return user.User{}, err
	}
	current, err := s.repository.UserByID(ctx, claims.Subject)
	if err != nil || isBlocked(current) {
		return user.User{}, ErrUnauthorized
	}
	return current, nil
}
