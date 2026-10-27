// Package service는 회원가입·로그인·계정 복구 흐름과 인증 정책을 담당합니다.
package service

import (
	"context"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// AuthRepository는 인증 service가 영속 저장소에 요청하는 작업을 정의합니다.
type AuthRepository interface {
	UserByLogin(context.Context, string) (model.User, error)
	UserByEmail(context.Context, string) (model.User, error)
	UserByID(context.Context, string) (model.User, error)
	EmailExists(context.Context, string) (bool, error)
	Terms(context.Context) ([]model.Term, error)
	CreateUserWithTerms(context.Context, model.Signup, []model.Consent) (model.User, error)
	InsertRefresh(context.Context, string, string, string, time.Time) error
	RevokeToken(context.Context, string) error
	RevokeAllTokens(context.Context, string) error
	RotateRefresh(context.Context, string, security.TokenManager, time.Duration) (model.Tokens, error)
	ResetPassword(context.Context, string, string, int64) error
	ChangePassword(context.Context, string, string, int64, string) error
	UpdateNickname(context.Context, string, string) (model.User, error)
	UpdateProfile(context.Context, string, string, string) (model.User, error)
	UpdateDisplayTheme(context.Context, string, string) (model.User, error)
}

// SignupCache는 Redis에 보관하는 임시 가입·인증·재설정 데이터의 작업을 정의합니다.
type SignupCache interface {
	CreateSignup(context.Context, string, string, string) error
	SetPassword(context.Context, string, string) error
	Signup(context.Context, string, string) (redisdb.SignupData, error)
	DeleteSignup(context.Context, string) error
	SaveCode(context.Context, string, string, string) error
	VerifyCode(context.Context, string, string) error
	Limit(context.Context, string, string, int, time.Duration) error
	SaveReset(context.Context, string, string, int64) error
	ConsumeReset(context.Context, string) (redisdb.ResetState, error)
}

// AuthService는 인증 흐름을 조정하고 저장소·메일·토큰 구현을 연결합니다.
type AuthService struct {
	// repository는 영속 데이터, cache는 만료가 필요한 임시 데이터만 담당합니다.
	// 두 저장소의 수명과 장애 특성이 다르므로 하나의 거대한 저장소로 합치지 않습니다.
	repository AuthRepository
	cache      SignupCache
	mailer     mailer.Sender
	tokens     security.TokenManager
	codeKey    []byte
	bcryptCost int
	refreshTTL time.Duration
}

// # 인증 서비스 생성 기능
func NewAuthService(repo AuthRepository, ephemeral SignupCache, sender mailer.Sender, tokens security.TokenManager, codeKey []byte, bcryptCost int, refreshTTL time.Duration) *AuthService {
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

// # 약관 목록 조회 기능
func (s *AuthService) Terms(ctx context.Context) ([]model.Term, error) {
	return s.repository.Terms(ctx)
}
