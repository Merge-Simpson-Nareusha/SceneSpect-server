package redis

import (
	"context"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// 발송 전에 password 단계와 누적 실패 횟수를 확인하고 이메일별 60초 잠금 키를
// 원자적으로 선점합니다. KEYS는 가입·인증코드·이메일 잠금 키, ARGV는 HMAC과 TTL입니다.
// 1은 저장 성공, 0은 가입 단계 오류, -1은 실패 횟수 또는 재전송 제한입니다.
var saveCode = goredis.NewScript(`
if redis.call('HGET', KEYS[1], 'stage') ~= 'password' then return 0 end
if tonumber(redis.call('HGET', KEYS[1], 'attempts') or '0') >= 5 then return -1 end
if not redis.call('SET', KEYS[3], '1', 'NX', 'EX', 60) then return -1 end
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
return 1`)

// # 인증 코드 저장 기능
func (e Ephemeral) SaveCode(ctx context.Context, id, email, hash string) error {
	n, err := saveCode.Run(ctx, e.Client, []string{signupKey(id), verifyKey(id), "email:cooldown:" + security.TokenHash(email)}, hash, CodeTTL.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if n == -1 {
		return response.ErrRateLimit
	}
	if n != 1 {
		return response.ErrState
	}
	return nil
}

// 비교·실패 횟수 증가·일회성 소비를 한 Lua 실행에서 처리해 동시 요청에 의한 제한 우회를 막습니다.
// 가입 세션의 attempts는 재전송해도 유지됩니다. 1은 인증 성공, 0은 잘못된 단계,
// -1은 코드 없음/불일치, -2는 이미 허용 실패 횟수에 도달했음을 뜻합니다.
var verifyCode = goredis.NewScript(`
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

// # 인증 코드 검증 기능
func (e Ephemeral) VerifyCode(ctx context.Context, id, hash string) error {
	n, err := verifyCode.Run(ctx, e.Client, []string{signupKey(id), verifyKey(id)}, hash).Int()
	if err != nil {
		return err
	}
	if n == -2 {
		return response.ErrRateLimit
	}
	if n == -1 {
		return response.ErrCode
	}
	if n != 1 {
		return response.ErrState
	}
	return nil
}
