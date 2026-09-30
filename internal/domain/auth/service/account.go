package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// ForgotPassword는 존재하지 않는 이메일에도 성공 경로를 반환해 계정 조회 여부를
// 응답으로 노출하지 않습니다. 계정이 있으면 요청 제한 확인 뒤에만 무작위 토큰을
// 만들고 Redis에 해시 키와 당시 비밀번호 버전을 저장한 다음 메일을 보냅니다.
func (s *AuthService) ForgotPassword(ctx context.Context, email, requestIP string) error {
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return nil
	}
	if err = s.cache.Limit(ctx, "password-forgot", requestIP, 5, time.Hour); err != nil {
		return err
	}
	current, err := s.repository.UserByEmail(ctx, normalized)
	if errors.Is(err, model.ErrUnauthorized) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := security.RandomToken()
	if err != nil {
		return err
	}
	if err = s.cache.SaveReset(ctx, raw, current.ID, current.PasswordVersion); err != nil {
		return err
	}
	if err = s.mailer.PasswordReset(current.Email, raw); err != nil {
		return errors.New("메일을 발송하지 못했습니다")
	}
	return nil
}

// ResetPassword는 일회용 재설정 토큰을 확인해 비밀번호를 바꾸고 기존 Refresh Token을 폐기합니다.
// 토큰 발급 시점의 비밀번호 버전과 현재 값이 다르면 요청을 거부합니다.
func (s *AuthService) ResetPassword(ctx context.Context, rawToken, password, confirmation string) error {
	if password != confirmation || len(rawToken) > 256 {
		return model.ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	reset, err := s.cache.ConsumeReset(ctx, rawToken)
	if err != nil {
		return model.ErrUnauthorized
	}
	current, err := s.repository.UserByID(ctx, reset.UserID)
	if err != nil || current.PasswordVersion != reset.PasswordVersion {
		return model.ErrUnauthorized
	}
	return s.repository.ResetPassword(ctx, current.ID, hash)
}

// FindAccount는 이메일 또는 로그인 아이디를 조회해 마스킹한 이메일과 아이디를 반환합니다.
// 계정 찾기 결과는 로그인 인증 수단으로 사용할 수 없습니다.
func (s *AuthService) FindAccount(ctx context.Context, login string) (model.AccountLookupResult, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	var current model.User
	var err error
	if strings.Contains(login, "@") {
		login, err = security.NormalizeEmail(login)
		if err != nil {
			return model.AccountLookupResult{}, model.ErrUnauthorized
		}
		current, err = s.repository.UserByEmail(ctx, login)
	} else {
		current, err = s.repository.UserByLogin(ctx, login)
	}
	if err != nil {
		return model.AccountLookupResult{}, err
	}
	return model.AccountLookupResult{Email: model.MaskEmail(current.Email), Username: current.Username}, nil
}

// isBlocked는 계정 상태만 판단합니다. USER/ADMIN 권한 비교는 authorization 도메인에
// 맡겨 인증 상태와 API 접근 정책이 서로 섞이지 않게 합니다.
func isBlocked(current model.User) bool {
	return strings.EqualFold(current.Status, "BLOCKED")
}
