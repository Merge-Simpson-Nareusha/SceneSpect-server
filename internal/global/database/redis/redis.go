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

type Ephemeral struct{ Client *goredis.Client }

// NewRedis는 HTTP 서버를 시작하기 전에 Redis 접속 문자열을 읽고 연결 가능 여부를 확인합니다.
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

type SignupData struct {
	Email, Nickname, PasswordHash string
}

// 내부 키에는 세션 ID 원문 대신 해시를 사용해 로그나 Redis key 목록에 자격 문자열이 드러나지 않게 합니다.
func signupKey(id string) string { return "signup:session:" + security.TokenHash(id) }
func verifyKey(id string) string { return "email:verify:" + security.TokenHash(id) }
