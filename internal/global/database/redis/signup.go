package redis

import (
	"context"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// 미완료 가입은 영속 회원이 아닙니다. Redis TTL로 생성 시점부터 30분 후 자동 제거해
// 중간에 이탈한 이메일과 해시의 보관 시간을 제한합니다. 다음 단계로 이동해도 이 TTL은 연장하지 않습니다.
// Lua에서는 KEYS[1]에 가입 정보를 만들고 ARGV[1..3]에 이메일·기본 닉네임·밀리초 TTL을 받습니다.
var createSignup = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'email', ARGV[1], 'nickname', ARGV[2], 'stage', 'email', 'attempts', 0)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1`)

// # 가입 세션 생성 기능
func (e Ephemeral) CreateSignup(ctx context.Context, id, email, nickname string) error {
	n, err := createSignup.Run(ctx, e.Client, []string{signupKey(id)}, email, nickname, SignupTTL.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if n != 1 {
		return response.ErrState
	}
	return nil
}

var setPassword = goredis.NewScript(`
if redis.call('HGET', KEYS[1], 'stage') ~= 'email' then return 0 end
redis.call('HSET', KEYS[1], 'password_hash', ARGV[1], 'stage', 'password')
return 1`)

// # 가입 비밀번호 저장 기능
func (e Ephemeral) SetPassword(ctx context.Context, id, hash string) error {
	n, err := setPassword.Run(ctx, e.Client, []string{signupKey(id)}, hash).Int()
	if err != nil {
		return err
	}
	if n != 1 {
		return response.ErrState
	}
	return nil
}

// # 가입 세션 조회 기능
func (e Ephemeral) Signup(ctx context.Context, id, stage string) (SignupData, error) {
	values, err := e.Client.HGetAll(ctx, signupKey(id)).Result()
	if err != nil {
		return SignupData{}, err
	}
	if values["stage"] != stage {
		return SignupData{}, response.ErrState
	}
	if (stage == "password" || stage == "verified") && values["password_hash"] == "" {
		return SignupData{}, response.ErrState
	}
	return SignupData{Email: values["email"], Nickname: values["nickname"], PasswordHash: values["password_hash"]}, nil
}

// # 가입 세션 삭제 기능
func (e Ephemeral) DeleteSignup(ctx context.Context, id string) error {
	return e.Client.Del(ctx, signupKey(id), verifyKey(id)).Err()
}
