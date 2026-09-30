package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// Login은 IP 요청 제한을 적용하고 이메일 또는 아이디와 비밀번호를 검증해 토큰을 발급합니다.
// 로그인 실패 사유는 동일한 인증 오류로 반환해 계정 상태를 노출하지 않습니다.
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

// issueTokens는 Access Token과 Refresh Token을 발급하고 Refresh Token의 해시만 DB에 저장합니다.
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

// Refresh는 입력 토큰을 확인한 뒤 repository의 트랜잭션 회전 절차로 새 토큰을 발급합니다.
func (s *AuthService) Refresh(ctx context.Context, raw string) (model.Tokens, error) {
	if raw == "" || len(raw) > 256 {
		return model.Tokens{}, model.ErrUnauthorized
	}
	return s.repository.RotateRefresh(ctx, raw, s.tokens, s.refreshTTL)
}

// Logout은 쿠키가 없으면 이미 로그아웃된 것으로 보고 성공 처리합니다.
// 토큰이 있을 때만 해시를 기준으로 해당 Refresh Token을 폐기합니다.
func (s *AuthService) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	return s.repository.RevokeToken(ctx, raw)
}

// Authenticate는 Access Token을 검증하고 최신 계정 상태를 조회해 현재 요청의 주체를 반환합니다.
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
