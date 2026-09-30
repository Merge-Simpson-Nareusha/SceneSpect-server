// Package service는 회원가입·로그인·계정 복구의 진행 순서와 규칙을 담당합니다.
// handler나 PostgreSQL repository 구현을 import하지 않고 인터페이스로 협력합니다.
package service

import (
	"context"
	"time"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
	redisdb "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/database/redis"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/mailer"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// AuthRepository는 서비스가 저장소에 요구하는 동작입니다.
// 사용하는 쪽인 service에 인터페이스를 두면 PostgreSQL 구현을 직접 import하지
// 않아도 됩니다. main에서 같은 메서드를 가진 repository를 연결합니다.
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
	ResetPassword(context.Context, string, string) error
}

// SignupCache keeps unfinished signup and reset flows in Redis with TTLs.
// auth 서비스는 Redis 명령을 직접 호출하지 않고 이 계약만 사용합니다.
// 그래서 저장소를 메모리 fake로 바꿔 회원가입 단계 테스트를 만들 수 있습니다.
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

// NewAuthService는 애플리케이션 조립부에서 한 번만 호출하는 생성자입니다.
// 토큰 키, bcrypt 비용, TTL 같은 보안 정책을 인자로 받아 전역 변수 의존을 피합니다.
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

func (s *AuthService) Terms(ctx context.Context) ([]model.Term, error) {
	// 약관 조회는 읽기 전용 repository 호출로 끝나며, 가입 완료 검증은
	// 클라이언트가 보낸 목록이 아니라 같은 repository의 현재 약관을 기준으로 합니다.
	return s.repository.Terms(ctx)
}
