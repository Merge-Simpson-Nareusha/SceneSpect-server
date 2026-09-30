package service

import (
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/authorization/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/security"
)

// Checker는 인증된 사용자가 API에서 요구하는 역할을 가졌는지 판단합니다.
type Checker struct{}

// Can은 사용자의 현재 역할이 필요한 역할과 일치하는지 반환합니다.
func (Checker) Can(current security.Principal, required model.Role) bool {
	return model.HasRole(current.Role, required)
}
