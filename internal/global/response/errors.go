package response

import "errors"

var (
	ErrInvalid      = errors.New("입력값을 확인해 주세요")
	ErrUnauthorized = errors.New("인증 정보가 올바르지 않거나 만료되었습니다")
	ErrForbidden    = errors.New("접근 권한이 없습니다")
	ErrNotFound     = errors.New("요청한 대상을 찾을 수 없습니다")
	ErrConflict     = errors.New("이미 사용 중인 값입니다")
	ErrTerms        = errors.New("현재 필수 약관에 모두 동의해야 합니다")
	ErrState        = errors.New("가입 세션이 만료되었거나 진행 순서가 올바르지 않습니다")
	ErrCode         = errors.New("인증코드가 올바르지 않거나 만료되었습니다")
	ErrRateLimit    = errors.New("요청 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요")
)
