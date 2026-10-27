package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/team/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

type UseCase interface {
	Create(c context.Context, userID, nickname string, input model.CreateTeam) (model.Team, error)
	List(context.Context, string) ([]model.Team, error)
	Get(context.Context, string, string) (model.Team, error)
	NameAvailable(context.Context, string, string) (bool, error)
	Update(context.Context, string, string, model.UpdateTeam) (model.Team, error)
	Delete(context.Context, string, string) error
	RequestJoin(context.Context, string, string, string) (model.JoinRequest, error)
	Requests(context.Context, string, string) ([]model.JoinRequest, error)
	ReviewRequest(context.Context, string, string, string, bool) error
	Members(context.Context, string, string) ([]model.Member, error)
	SetRole(context.Context, string, string, string, model.Role) error
	SetProjectCreation(context.Context, string, string, string, bool) error
	RemoveMember(context.Context, string, string, string) error
	WarnMember(context.Context, string, string, string) (int, error)
	Reorder(context.Context, string, []string) error
}

type TeamHandler struct{ service UseCase }

func NewTeamHandler(service UseCase) *TeamHandler { return &TeamHandler{service: service} }

func (h *TeamHandler) Register(routes *gin.RouterGroup, auth gin.HandlerFunc) {
	teams := routes.Group("/teams", auth)
	teams.GET("", h.List)
	teams.POST("", h.Create)
	teams.GET("/name-availability", h.NameAvailability)
	teams.PUT("/order", h.Reorder)
	teams.POST("/join-requests", h.Join)
	teams.GET("/:teamId", h.Get)
	teams.PATCH("/:teamId", h.Update)
	teams.DELETE("/:teamId", h.Delete)
	teams.GET("/:teamId/members", h.Members)
	teams.DELETE("/:teamId/members/:userId", h.RemoveMember)
	teams.POST("/:teamId/members/:userId/warnings", h.WarnMember)
	teams.PATCH("/:teamId/members/:userId/role", h.SetRole)
	teams.PATCH("/:teamId/members/:userId/permissions", h.SetProjectCreation)
	teams.GET("/:teamId/join-requests", h.Requests)
	teams.PATCH("/:teamId/join-requests/:requestId", h.ReviewRequest)
}

func (h *TeamHandler) Create(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.CreateTeam
	if !response.BindJSON(c, &input) {
		return
	}
	team, err := h.service.Create(c.Request.Context(), user.ID, user.Nickname, input)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"team": team})
}

func (h *TeamHandler) List(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	teams, err := h.service.List(c.Request.Context(), user.ID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"teams": teams})
}

func (h *TeamHandler) Get(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	team, err := h.service.Get(c.Request.Context(), user.ID, c.Param("teamId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"team": team})
}

func (h *TeamHandler) NameAvailability(c *gin.Context) {
	nameAvailable, err := h.service.NameAvailable(c.Request.Context(), c.Query("name"), c.Query("excludeTeamId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"available": nameAvailable})
}

func (h *TeamHandler) Update(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.UpdateTeam
	if !response.BindJSON(c, &input) {
		return
	}
	team, err := h.service.Update(c.Request.Context(), user.ID, c.Param("teamId"), input)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"team": team})
}

func (h *TeamHandler) Delete(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	if err := h.service.Delete(c.Request.Context(), user.ID, c.Param("teamId")); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TeamHandler) Join(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.JoinTeam
	if !response.BindJSON(c, &input) {
		return
	}
	request, err := h.service.RequestJoin(c.Request.Context(), user.ID, input.JoinCode, input.Nickname)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"request": request})
}

func (h *TeamHandler) Members(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	members, err := h.service.Members(c.Request.Context(), user.ID, c.Param("teamId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"members": members})
}

func (h *TeamHandler) Requests(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	requests, err := h.service.Requests(c.Request.Context(), user.ID, c.Param("teamId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"requests": requests})
}

func (h *TeamHandler) ReviewRequest(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.ReviewRequest
	if !response.BindJSON(c, &input) {
		return
	}
	if err := h.service.ReviewRequest(c.Request.Context(), user.ID, c.Param("teamId"), c.Param("requestId"), input.Accept); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TeamHandler) SetRole(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.SetRole
	if !response.BindJSON(c, &input) {
		return
	}
	if err := h.service.SetRole(c.Request.Context(), user.ID, c.Param("teamId"), c.Param("userId"), input.Role); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TeamHandler) SetProjectCreation(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.MemberPermission
	if !response.BindJSON(c, &input) {
		return
	}
	if err := h.service.SetProjectCreation(c.Request.Context(), user.ID, c.Param("teamId"), c.Param("userId"), input.CanCreateProjects); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TeamHandler) RemoveMember(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	if err := h.service.RemoveMember(c.Request.Context(), user.ID, c.Param("teamId"), c.Param("userId")); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TeamHandler) WarnMember(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	count, err := h.service.WarnMember(c.Request.Context(), user.ID, c.Param("teamId"), c.Param("userId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"warningCount": count})
}

func (h *TeamHandler) Reorder(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.ReorderTeams
	if !response.BindJSON(c, &input) {
		return
	}
	if err := h.service.Reorder(c.Request.Context(), user.ID, input.TeamIDs); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func respondError(c *gin.Context, err error) {
	response.RespondError(c, response.StatusFor(err), err)
}
