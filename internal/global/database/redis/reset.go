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

func (e Ephemeral) SaveReset(ctx context.Context, raw, userID string, passwordVersion int64) error {
	// 비밀번호 재설정 토큰은 원문 대신 해시 키로 저장하고, 당시 passwordVersion을
	// 함께 기록해 이후 비밀번호 변경 여부를 검증할 수 있게 합니다.
	value, err := json.Marshal(ResetState{userID, passwordVersion})
	if err != nil {
		return err
	}
	return e.Client.Set(ctx, "password:reset:"+security.TokenHash(raw), value, ResetTTL).Err()
}

// GET과 DEL을 한 원자 연산으로 실행해 같은 토큰을 동시에 제출해도 한 요청만 얻습니다.
// 토큰 원문은 Redis key에 사용하지 않고 security.TokenHash 결과를 key에 붙입니다.
var consumeReset = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return false end
redis.call('DEL', KEYS[1])
return value`)

// 토큰 조회와 삭제를 하나의 Redis 명령으로 묶어 비밀번호 재설정 토큰의 재사용을 막습니다.
func (e Ephemeral) ConsumeReset(ctx context.Context, raw string) (ResetState, error) {
	// GET 후 DEL을 별도 명령으로 실행하면 동시 요청이 같은 토큰을 함께 사용할 수
	// 있으므로 Lua 스크립트에서 조회와 삭제를 원자적으로 처리합니다.
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

func (e Ephemeral) DeleteReset(ctx context.Context, raw string) error {
	return e.Client.Del(ctx, "password:reset:"+security.TokenHash(raw)).Err()
}
