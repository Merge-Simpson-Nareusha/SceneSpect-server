package service

import (
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// Checker는 인증된 Principal이 요구 역할을 가졌는지 판단하는 인가 정책 서비스입니다.
// HTTP middleware에서 Gin 요청 정보를 떼어 냈으므로 다른 도메인 서비스나
// 백그라운드 작업도 HTTP 컨텍스트 없이 같은 역할 정책을 호출할 수 있습니다.
type Checker struct{}

// Can은 현재 역할과 요구 역할을 정확히 비교합니다. HTTP 응답이나 다음 핸들러 실행은
// 이 계층이 아니라 middleware가 결정합니다.
func (Checker) Can(current security.Principal, required model.Role) bool {
	return model.HasRole(current.Role, required)
}
