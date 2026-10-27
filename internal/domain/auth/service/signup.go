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

// # 가입 세션 시작 기능
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

// # 가입 비밀번호 설정 기능
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

// # 가입 이메일 인증 코드 발송 기능
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

// # 가입 이메일 인증 코드 확인 기능
func (s *AuthService) VerifySignupCode(ctx context.Context, sessionID, code string) error {
	if !sixDigitCode.MatchString(code) {
		return model.ErrCode
	}
	return s.cache.VerifyCode(ctx, sessionID, security.CodeHash(s.codeKey, sessionID, code))
}

// # 약관 동의 확인 및 회원가입 완료 기능
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
