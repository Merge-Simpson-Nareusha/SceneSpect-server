package handler

import "github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"

// 이 구조체들은 HTTP JSON 요청에만 쓰입니다. binding 태그가 기본 필수 입력을
// 확인하지만 이메일·비밀번호 정책과 가입 단계는 service가 다시 검증합니다.
// 그래서 DB 모델을 요청 본문으로 직접 쓰거나 HTTP 입력만 믿지 않습니다.

// signupStartRequest는 가입을 시작할 때 이메일만 받습니다. 닉네임은 이 값을
// 정규화한 뒤 서버가 만들기 때문에 클라이언트가 기본 아이디를 지정하지 않습니다.
type signupStartRequest struct {
	Email string `json:"email" binding:"required"`
}

// passwordRequest는 이메일 단계에서 만들어진 가입 세션에 비밀번호를 연결합니다.
// 두 비밀번호의 일치 여부와 길이 정책은 해시를 만들기 전에 service가 확인합니다.
type passwordRequest struct {
	SignupSessionID      string `json:"signupSessionId" binding:"required"`
	Password             string `json:"password" binding:"required"`
	PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
}

// sessionRequest는 이메일 인증번호 발송처럼 특정 가입 세션을 다음 단계로
// 진행시키는 요청에서 공통으로 사용합니다.
type sessionRequest struct {
	SignupSessionID string `json:"signupSessionId" binding:"required"`
}

// verifyRequest의 code는 메일로 받은 6자리 코드입니다. 세션 ID와 코드를 함께
// 보내면 service가 HMAC 비교와 실패 횟수 제한을 거쳐 인증 단계를 바꿉니다.
type verifyRequest struct {
	SignupSessionID string `json:"signupSessionId" binding:"required"`
	Code            string `json:"code" binding:"required"`
}

// consentRequest는 사용자가 약관별로 동의했는지 전달합니다. 이 목록은
// 영구 저장 전에 DB의 현재 약관 목록과 대조되므로 클라이언트가 약관을 추가하거나
// 필수 동의를 생략해도 가입을 완료할 수 없습니다.
type consentRequest struct {
	SignupSessionID string          `json:"signupSessionId" binding:"required"`
	Consents        []model.Consent `json:"consents" binding:"required"`
}

// loginRequest.login에는 이메일이나 서버가 만든 고정 아이디를 넣을 수 있습니다.
// 비밀번호와 로그인 값을 같은 본문으로 보내며 응답 형식은 handler가 정합니다.
type loginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// emailRequest는 비밀번호 재설정 안내 요청에 사용합니다.
type emailRequest struct {
	Email string `json:"email" binding:"required"`
}

// resetRequest는 일회용 재설정 토큰과 새 비밀번호를 받습니다. 토큰 소비,
// bcrypt 해시 생성, Refresh Token 폐기는 service와 repository가 담당합니다.
type resetRequest struct {
	Token                string `json:"token" binding:"required"`
	Password             string `json:"password" binding:"required"`
	PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
}

// findRequest는 이메일 또는 고정 아이디로 계정을 찾기 위한 입력입니다.
type findRequest struct {
	Login string `json:"login" binding:"required"`
}
