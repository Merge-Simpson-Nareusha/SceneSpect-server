package service

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

var sixDigitCode = regexp.MustCompile(`^[0-9]{6}$`)

// StartSignup은 이메일 중복을 확인하고 기본 닉네임을 정한 뒤 Redis에 임시 가입 세션을 만듭니다.
func (s *AuthService) StartSignup(ctx context.Context, email, requestIP string) (model.SignupStartResult, error) {
	if err := s.cache.Limit(ctx, "signup-start", requestIP, 10, time.Hour); err != nil {
		return model.SignupStartResult{}, err
	}
	normalized, err := security.NormalizeEmail(email)
	if err != nil {
		return model.SignupStartResult{}, err
	}
	exists, err := s.repository.EmailExists(ctx, normalized)
	if err != nil {
		return model.SignupStartResult{}, err
	}
	if exists {
		return model.SignupStartResult{}, model.ErrConflict
	}

	nickname := security.NicknameBase(normalized)
	if !security.ValidNickname(nickname) {
		return model.SignupStartResult{}, model.ErrInvalid
	}
	sessionID := uuid.NewString()
	if err := s.cache.CreateSignup(ctx, sessionID, normalized, nickname); err != nil {
		return model.SignupStartResult{}, err
	}
	return model.SignupStartResult{SignupSessionID: sessionID, Email: normalized, Nickname: nickname, ExpiresIn: int64(redisdb.SignupTTL.Seconds())}, nil
}

// SetSignupPassword는 email 단계의 세션에 비밀번호 해시를 저장하고 다음 단계로 이동합니다.
func (s *AuthService) SetSignupPassword(ctx context.Context, sessionID, password, confirmation string) error {
	if password != confirmation {
		return model.ErrInvalid
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return model.ErrInvalid
	}
	hash, err := security.HashPassword(password, s.bcryptCost)
	if err != nil {
		return err
	}
	return s.cache.SetPassword(ctx, sessionID, hash)
}

// SendSignupCode는 password 단계 세션에 6자리 코드를 보내고 Redis에는 HMAC 값으로 저장합니다.
// 발송 횟수와 재전송 대기 시간은 IP·이메일 기준으로 제한합니다.
func (s *AuthService) SendSignupCode(ctx context.Context, sessionID, requestIP string) (model.VerificationResult, error) {
	signup, err := s.cache.Signup(ctx, sessionID, "password")
	if err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send", signup.Email, 5, time.Hour); err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.cache.Limit(ctx, "email-send-ip", requestIP, 20, time.Hour); err != nil {
		return model.VerificationResult{}, err
	}
	code, err := security.NewCode()
	if err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.cache.SaveCode(ctx, sessionID, signup.Email, security.CodeHash(s.codeKey, sessionID, code)); err != nil {
		return model.VerificationResult{}, err
	}
	if err = s.mailer.Verification(signup.Email, code); err != nil {
		return model.VerificationResult{}, errors.New("메일을 발송하지 못했습니다")
	}
	return model.VerificationResult{ExpiresIn: int64(redisdb.CodeTTL.Seconds()), ResendAfter: 60}, nil
}

// VerifySignupCode는 입력 형식부터 확인하고 일치 여부는 Redis에서 검사합니다.
// 맞는 코드는 한 번만 소비되고 세션은 verified 단계로 이동합니다. 틀린 코드는
// 재전송으로 초기화되지 않는 누적 실패 횟수를 올립니다.
func (s *AuthService) VerifySignupCode(ctx context.Context, sessionID, code string) error {
	if !sixDigitCode.MatchString(code) {
		return model.ErrCode
	}
	return s.cache.VerifyCode(ctx, sessionID, security.CodeHash(s.codeKey, sessionID, code))
}

// CompleteSignup은 이메일 인증과 필수 약관 동의를 확인해 회원을 생성하고 로그인 토큰을 발급합니다.
// 회원 생성 후 토큰 발급이 실패하면 가입을 반복하지 않고 일반 로그인으로 이어가야 합니다.
func (s *AuthService) CompleteSignup(ctx context.Context, sessionID string, consents []model.Consent) (model.Tokens, error) {
	signupData, err := s.cache.Signup(ctx, sessionID, "verified")
	if err != nil {
		return model.Tokens{}, err
	}
	signup := model.Signup{Email: signupData.Email, Nickname: signupData.Nickname, PasswordHash: signupData.PasswordHash}
	user, err := s.repository.CreateUserWithTerms(ctx, signup, consents)
	if err != nil {
		return model.Tokens{}, err
	}
	// 영속 회원 생성 후 임시 상태는 제거합니다. 삭제 실패가 이미 완료된 가입을 되돌리지는 않습니다.
	_ = s.cache.DeleteSignup(ctx, sessionID)
	return s.issueTokens(ctx, user)
}
