package user

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

type Handler struct {
	service Service
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Me(c *gin.Context) {
	current, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": current})
}

func (h *Handler) UpdateNickname(c *gin.Context) {
	var request NicknameRequest
	if !response.BindJSON(c, &request) {
		return
	}
	current, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	updated, err := h.service.UpdateNickname(c.Request.Context(), current.ID, request.Nickname)
	if err != nil {
		response.RespondError(c, response.StatusFor(err), err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": updated})
}
