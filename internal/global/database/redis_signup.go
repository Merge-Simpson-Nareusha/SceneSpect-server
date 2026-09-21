package database

import (
	"context"

	"github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

// 미완료 가입은 영속 회원이 아닙니다. Redis TTL로 30분 후 자동 제거하고 개인정보 보관을 줄입니다.
var createSignup = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'email', ARGV[1], 'nickname', ARGV[2], 'stage', 'email', 'attempts', 0)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1`)

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
		return response.ErrState
	}
	return nil
}

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

func (e Ephemeral) DeleteSignup(ctx context.Context, id string) error {
	return e.Client.Del(ctx, signupKey(id), verifyKey(id)).Err()
}
