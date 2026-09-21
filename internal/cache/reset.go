package cache

import (
	"context"
	"encoding/json"

	"github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

type ResetState struct {
	UserID          string `json:"userId"`
	PasswordVersion int64  `json:"version"`
}

func (e Ephemeral) SaveReset(ctx context.Context, raw string, user domain.User) error {
	value, err := json.Marshal(ResetState{user.ID, user.PasswordVersion})
	if err != nil {
		return err
	}
	return e.Client.Set(ctx, "password:reset:"+security.TokenHash(raw), value, ResetTTL).Err()
}

var consumeReset = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return false end
redis.call('DEL', KEYS[1])
return value`)

// 토큰 조회와 삭제를 하나의 Redis 명령으로 묶어 비밀번호 재설정 토큰의 재사용을 막습니다.
func (e Ephemeral) ConsumeReset(ctx context.Context, raw string) (ResetState, error) {
	var state ResetState
	value, err := consumeReset.Run(ctx, e.Client, []string{"password:reset:" + security.TokenHash(raw)}).Result()
	if err == redis.Nil {
		return state, domain.ErrUnauthorized
	}
	if err != nil {
		return state, err
	}
	encoded, ok := value.(string)
	if !ok {
		return state, domain.ErrUnauthorized
	}
	if err = json.Unmarshal([]byte(encoded), &state); err != nil {
		return state, err
	}
	return state, nil
}

func (e Ephemeral) DeleteReset(ctx context.Context, raw string) error {
	return e.Client.Del(ctx, "password:reset:"+security.TokenHash(raw)).Err()
}
