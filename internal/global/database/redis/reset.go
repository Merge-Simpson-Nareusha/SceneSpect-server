package redis

import (
	"context"
	"encoding/json"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

type ResetState struct {
	// 토큰 발급 이후 비밀번호가 바뀌지 않았는지 확인하는 버전입니다.
	UserID          string `json:"userId"`
	PasswordVersion int64  `json:"version"`
}

// # 비밀번호 재설정 토큰 저장 기능
func (e Ephemeral) SaveReset(ctx context.Context, raw, userID string, passwordVersion int64) error {
	value, err := json.Marshal(ResetState{userID, passwordVersion})
	if err != nil {
		return err
	}
	return e.Client.Set(ctx, "password:reset:"+security.TokenHash(raw), value, ResetTTL).Err()
}

// consumeReset은 토큰 조회와 삭제를 원자적으로 처리해 한 요청만 토큰을 사용할 수 있게 합니다.
var consumeReset = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return false end
redis.call('DEL', KEYS[1])
return value`)

// # 비밀번호 재설정 토큰 소비 기능
func (e Ephemeral) ConsumeReset(ctx context.Context, raw string) (ResetState, error) {
	var state ResetState
	value, err := consumeReset.Run(ctx, e.Client, []string{"password:reset:" + security.TokenHash(raw)}).Result()
	if err == goredis.Nil {
		return state, response.ErrUnauthorized
	}
	if err != nil {
		return state, err
	}
	encoded, ok := value.(string)
	if !ok {
		return state, response.ErrUnauthorized
	}
	if err = json.Unmarshal([]byte(encoded), &state); err != nil {
		return state, err
	}
	return state, nil
}

// # 비밀번호 재설정 토큰 삭제 기능
func (e Ephemeral) DeleteReset(ctx context.Context, raw string) error {
	return e.Client.Del(ctx, "password:reset:"+security.TokenHash(raw)).Err()
}
