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
	// 존재하지 않는 이메일도 성공처럼 처리해 계정 열거를 막습니다. 실제 계정일 때만
	// Redis에 일회성 reset 상태를 저장하고 메일을 보냅니다.
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

// ResetPassword는 비밀번호 확인과 길이 제한을 검사하고 새 해시를 준비합니다.
// 이어 Redis에서 일회용 토큰을 소비하고 발급 당시 비밀번호 버전과 현재 값을
// 비교합니다. 최종 변경과 모든 기존 Refresh Token 폐기는 repository 트랜잭션입니다.
func (s *AuthService) ResetPassword(ctx context.Context, rawToken, password, confirmation string) error {
	// ConsumeReset은 읽기와 삭제를 원자적으로 처리합니다. PasswordVersion도 함께
	// 비교해 이미 비밀번호가 바뀐 뒤 발급된 토큰을 재사용하지 못하게 합니다.
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

// FindAccount는 @ 포함 여부로 이메일과 고정 아이디를 구분해 조회합니다.
// 성공하면 이메일은 일부만 보여 주지만 아이디는 그대로 돌려주며, 계정이 없으면
// handler에서 404로 바뀝니다. 따라서 이 결과는 인증 수단이 아니라 계정 찾기 안내입니다.
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
	// 상태 판정은 대소문자 차이를 허용하지 않지만, 역할(Role) 판정은
	// authorization 패키지에서 정확히 비교합니다.
	return strings.EqualFold(current.Status, "BLOCKED")
}
