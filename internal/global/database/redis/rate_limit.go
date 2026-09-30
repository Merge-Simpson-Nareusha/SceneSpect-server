package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// 고정 구간 제한입니다. 첫 요청이 카운터와 만료 시각을 만들고 이후 요청은 같은
// 구간의 숫자만 올립니다. INCR와 최초 PEXPIRE를 분리하면 동시 요청 중 TTL이
// 빠지는 경우가 생길 수 있으므로 한 Lua 실행 안에서 함께 처리합니다.
var rateLimit = goredis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
if n > tonumber(ARGV[2]) then return 0 end
return 1`)

// Limit은 요청 종류와 이메일·IP별 고정 구간 횟수를 세고, 초과 시 제한 오류를 반환합니다.
func (e Ephemeral) Limit(ctx context.Context, bucket, identity string, limit int, window time.Duration) error {
	// Redis 키에 이메일이나 IP 원문이 남지 않도록 identity를 해시합니다.
	n, err := rateLimit.Run(ctx, e.Client, []string{"ratelimit:" + bucket + ":" + security.TokenHash(identity)}, window.Milliseconds(), limit).Int()
	if err != nil {
		return err
	}
	if n != 1 {
		return response.ErrRateLimit
	}
	return nil
}
