package service

import (
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// Checker는 인증된 사용자가 API에서 요구하는 역할을 가졌는지 판단합니다.
type Checker struct{}

// # 역할 권한 확인 기능
func (Checker) Can(current security.Principal, required model.Role) bool {
	return model.HasRole(current.Role, required)
}
