package user

type NicknameRequest struct {
	Nickname string `json:"nickname" binding:"required"`
}
