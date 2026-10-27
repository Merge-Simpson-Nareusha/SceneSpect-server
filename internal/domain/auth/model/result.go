package model

// 결과 타입은 HTTP 태그 없이 서비스 처리 결과만 담습니다.
// handler에서 화면에 필요한 JSON 필드로 변환하므로 서비스는 Gin을 몰라도 됩니다.
type SignupStartResult struct {
	// ExpiresIn을 프론트에 알려 사용자가 세션 만료 전에 다음 단계를 진행하게 합니다.
	SignupSessionID string
	Email           string
	Nickname        string
	ExpiresIn       int64
}

type VerificationResult struct {
	ExpiresIn int64
	// ResendAfter는 화면이 재전송 버튼을 잠시 비활성화할 수 있도록 안내합니다.
	// 실제 재전송 허용 여부는 Redis가 검사하므로 클라이언트의 타이머는 보안 경계가 아닙니다.
	ResendAfter int64
}

type AccountLookupResult struct {
	// Email은 평문 주소가 아니라 일부를 가린 값으로 handler에 전달합니다.
	Email    string
	Username string
}
