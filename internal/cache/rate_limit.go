package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

var rateLimit = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
if n > tonumber(ARGV[2]) then return 0 end
return 1`)

func (e Ephemeral) Limit(ctx context.Context, bucket, identity string, limit int, window time.Duration) error {
	n, err := rateLimit.Run(ctx, e.Client, []string{"ratelimit:" + bucket + ":" + security.TokenHash(identity)}, window.Milliseconds(), limit).Int()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.ErrRateLimit
	}
	return nil
}
