// Package cache contains Redis-backed, TTL-bound authentication state.
package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/security"
)

const SignupTTL = 30 * time.Minute
const CodeTTL = 5 * time.Minute
const ResetTTL = 15 * time.Minute

type Ephemeral struct{ Client *redis.Client }

// 미완료 가입은 영속 회원이 아닙니다. Redis TTL로 30분 후 자동 제거하고 개인정보 보관을 줄입니다.
var createSignup = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'email', ARGV[1], 'nickname', ARGV[2], 'stage', 'email', 'attempts', 0)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1`)

func signupKey(id string) string { return "signup:session:" + security.TokenHash(id) }
func verifyKey(id string) string { return "email:verify:" + security.TokenHash(id) }

func (e Ephemeral) CreateSignup(ctx context.Context, id, email, nickname string) error {
	n, err := createSignup.Run(ctx, e.Client, []string{signupKey(id)}, email, nickname, SignupTTL.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.ErrState
	}
	return nil
}

var setPassword = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'stage') ~= 'email' then return 0 end
redis.call('HSET', KEYS[1], 'password_hash', ARGV[1], 'stage', 'password')
return 1`)

func (e Ephemeral) SetPassword(ctx context.Context, id, hash string) error {
	n, err := setPassword.Run(ctx, e.Client, []string{signupKey(id)}, hash).Int()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.ErrState
	}
	return nil
}

var saveCode = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'stage') ~= 'password' then return 0 end
if tonumber(redis.call('HGET', KEYS[1], 'attempts') or '0') >= 5 then return -1 end
if not redis.call('SET', KEYS[3], '1', 'NX', 'EX', 60) then return -1 end
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
return 1`)

func (e Ephemeral) SaveCode(ctx context.Context, id, email, hash string) error {
	n, err := saveCode.Run(ctx, e.Client, []string{signupKey(id), verifyKey(id), "email:cooldown:" + security.TokenHash(email)}, hash, CodeTTL.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if n == -1 {
		return domain.ErrRateLimit
	}
	if n != 1 {
		return domain.ErrState
	}
	return nil
}

// 비교·실패 횟수 증가·일회성 소비를 한 Lua 실행에서 처리해 동시 요청에 의한 제한 우회를 막습니다.
// 재전송해도 가입 세션의 누적 실패 횟수는 초기화하지 않습니다.
var verifyCode = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'stage') ~= 'password' then return 0 end
if tonumber(redis.call('HGET', KEYS[1], 'attempts') or '0') >= 5 then return -2 end
local expected = redis.call('GET', KEYS[2])
if not expected then return -1 end
if expected ~= ARGV[1] then
  local count = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
  if count >= 5 then redis.call('DEL', KEYS[2]) end
  return -1
end
redis.call('DEL', KEYS[2])
redis.call('HSET', KEYS[1], 'stage', 'verified')
return 1`)

func (e Ephemeral) VerifyCode(ctx context.Context, id, hash string) error {
	n, err := verifyCode.Run(ctx, e.Client, []string{signupKey(id), verifyKey(id)}, hash).Int()
	if err != nil {
		return err
	}
	if n == -2 {
		return domain.ErrRateLimit
	}
	if n == -1 {
		return domain.ErrCode
	}
	if n != 1 {
		return domain.ErrState
	}
	return nil
}

func (e Ephemeral) Signup(ctx context.Context, id, stage string) (domain.Signup, error) {
	v, err := e.Client.HGetAll(ctx, signupKey(id)).Result()
	if err != nil {
		return domain.Signup{}, err
	}
	if v["stage"] != stage {
		return domain.Signup{}, domain.ErrState
	}
	if (stage == "password" || stage == "verified") && v["password_hash"] == "" {
		return domain.Signup{}, domain.ErrState
	}
	return domain.Signup{Email: v["email"], Nickname: v["nickname"], PasswordHash: v["password_hash"]}, nil
}

func (e Ephemeral) DeleteSignup(ctx context.Context, id string) error {
	return e.Client.Del(ctx, signupKey(id), verifyKey(id)).Err()
}

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

type ResetState struct {
	UserID          string `json:"userId"`
	PasswordVersion int64  `json:"version"`
}

var consumeReset = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return false end
redis.call('DEL', KEYS[1])
return value`)

func (e Ephemeral) SaveReset(ctx context.Context, raw string, user domain.User) error {
	b, err := json.Marshal(ResetState{user.ID, user.PasswordVersion})
	if err != nil {
		return err
	}
	return e.Client.Set(ctx, "password:reset:"+security.TokenHash(raw), b, ResetTTL).Err()
}

func (e Ephemeral) Reset(ctx context.Context, raw string) (ResetState, error) {
	var s ResetState
	b, err := e.Client.Get(ctx, "password:reset:"+security.TokenHash(raw)).Bytes()
	if err == redis.Nil {
		return s, domain.ErrUnauthorized
	}
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal([]byte(b), &s); err != nil {
		return s, err
	}
	return s, nil
}

// 토큰 조회와 삭제를 하나의 Redis 명령으로 묶어 비밀번호 재설정 토큰의 재사용을 막습니다.
func (e Ephemeral) ConsumeReset(ctx context.Context, raw string) (ResetState, error) {
	var s ResetState
	value, err := consumeReset.Run(ctx, e.Client, []string{"password:reset:" + security.TokenHash(raw)}).Result()
	if err == redis.Nil {
		return s, domain.ErrUnauthorized
	}
	if err != nil {
		return s, err
	}
	b, ok := value.(string)
	if !ok {
		return s, domain.ErrUnauthorized
	}
	if err = json.Unmarshal([]byte(b), &s); err != nil {
		return s, err
	}
	return s, nil
}

func (e Ephemeral) DeleteReset(ctx context.Context, raw string) error {
	return e.Client.Del(ctx, "password:reset:"+security.TokenHash(raw)).Err()
}
