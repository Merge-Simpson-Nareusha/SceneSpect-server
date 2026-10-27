// Package redis는 Redis 연결과 TTL 기반 임시 데이터를 관리합니다.
// PostgreSQL에 영속 저장할 데이터와 구분해 만료·원자 연산 정책을 한곳에 둡니다.
package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

const (
	// TTL 정책은 가입 개인정보와 인증 자격의 보관 시간을 짧게 유지하기 위한
	// 중앙 정책입니다. 기능별 코드에 숫자를 흩뿌리지 않습니다.
	SignupTTL = 30 * time.Minute
	CodeTTL   = 5 * time.Minute
	ResetTTL  = 15 * time.Minute
)

// Ephemeral은 만료가 필요한 가입·인증·재설정 데이터를 Redis에서 처리합니다.
type Ephemeral struct{ Client *goredis.Client }

// # Redis 연결 생성 기능
func NewRedis(ctx context.Context, redisURL string) (*goredis.Client, error) {
	// Redis URL 파싱과 Ping을 이 계층에서 처리해 main은 연결 방식보다 의존성
	// 조립 순서에 집중할 수 있습니다.
	options, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	client := goredis.NewClient(options)
	if err = client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

// SignupData는 Redis의 임시 가입 세션에서 읽은 이메일·닉네임·비밀번호 해시입니다.
type SignupData struct {
	Email, Nickname, PasswordHash string
}

// # 가입 세션 키 생성 기능
func signupKey(id string) string { return "signup:session:" + security.TokenHash(id) }

// # 이메일 인증 키 생성 기능
func verifyKey(id string) string { return "email:verify:" + security.TokenHash(id) }
