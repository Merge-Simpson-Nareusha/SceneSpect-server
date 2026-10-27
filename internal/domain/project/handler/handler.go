package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/project/model"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/middleware"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

type UseCase interface {
	Create(context.Context, string, string, model.CreateProject) (model.Project, error)
	List(context.Context, string, string, string) ([]model.Project, error)
	Get(context.Context, string, string) (model.Project, error)
	Update(context.Context, string, string, model.UpdateProject) (model.Project, error)
	Delete(context.Context, string, string) error
	Members(context.Context, string, string) ([]model.ProjectMember, error)
	Grant(context.Context, string, string, string, model.AccessLevel) error
	Revoke(context.Context, string, string, string) error
	RequestAccess(context.Context, string, string, model.RequestAccess) (model.AccessRequest, error)
	AccessRequests(context.Context, string, string) ([]model.AccessRequest, error)
	ReviewAccess(context.Context, string, string, string, bool) error
	RequestDeletion(context.Context, string, string, string) (model.DeleteRequest, error)
	DeleteRequests(context.Context, string, string) ([]model.DeleteRequest, error)
	ReviewDeletion(context.Context, string, string, string, bool) error
}

type ProjectHandler struct{ service UseCase }

func NewProjectHandler(service UseCase) *ProjectHandler { return &ProjectHandler{service: service} }

func (h *ProjectHandler) Register(routes *gin.RouterGroup, auth gin.HandlerFunc) {
	teams := routes.Group("/teams/:teamId", auth)
	teams.GET("/projects", h.List)
	teams.POST("/projects", h.Create)
	teams.GET("/project-access-requests", h.AccessRequests)
	teams.PATCH("/project-access-requests/:requestId", h.ReviewAccess)
	teams.GET("/project-delete-requests", h.DeleteRequests)
	teams.PATCH("/project-delete-requests/:requestId", h.ReviewDeletion)

	projects := routes.Group("/projects", auth)
	projects.GET("/:projectId", h.Get)
	projects.PATCH("/:projectId", h.Update)
	projects.DELETE("/:projectId", h.Delete)
	projects.GET("/:projectId/members", h.Members)
	projects.PUT("/:projectId/permissions/:userId", h.Grant)
	projects.DELETE("/:projectId/permissions/:userId", h.Revoke)
	projects.POST("/:projectId/access-requests", h.RequestAccess)
	projects.POST("/:projectId/delete-requests", h.RequestDeletion)
}

func (h *ProjectHandler) Create(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.CreateProject
	if !response.BindJSON(c, &input) {
		return
	}
	project, err := h.service.Create(c.Request.Context(), user.ID, c.Param("teamId"), input)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"project": project})
}

func (h *ProjectHandler) List(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	projects, err := h.service.List(c.Request.Context(), user.ID, c.Param("teamId"), c.Query("sort"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"projects": projects})
}

func (h *ProjectHandler) Get(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	project, err := h.service.Get(c.Request.Context(), user.ID, c.Param("projectId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"project": project})
}

func (h *ProjectHandler) Update(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.UpdateProject
	if !response.BindJSON(c, &input) {
		return
	}
	project, err := h.service.Update(c.Request.Context(), user.ID, c.Param("projectId"), input)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"project": project})
}

func (h *ProjectHandler) Delete(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	if err := h.service.Delete(c.Request.Context(), user.ID, c.Param("projectId")); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ProjectHandler) Members(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	members, err := h.service.Members(c.Request.Context(), user.ID, c.Param("projectId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"members": members})
}

func (h *ProjectHandler) Grant(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.GrantAccess
	if !response.BindJSON(c, &input) {
		return
	}
	if err := h.service.Grant(c.Request.Context(), user.ID, c.Param("projectId"), c.Param("userId"), input.AccessLevel); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ProjectHandler) Revoke(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	if err := h.service.Revoke(c.Request.Context(), user.ID, c.Param("projectId"), c.Param("userId")); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ProjectHandler) RequestAccess(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.RequestAccess
	if !response.BindJSON(c, &input) {
		return
	}
	request, err := h.service.RequestAccess(c.Request.Context(), user.ID, c.Param("projectId"), input)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"request": request})
}

func (h *ProjectHandler) AccessRequests(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	requests, err := h.service.AccessRequests(c.Request.Context(), user.ID, c.Param("teamId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"requests": requests})
}

func (h *ProjectHandler) ReviewAccess(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.ReviewRequest
	if !response.BindJSON(c, &input) {
		return
	}
	if err := h.service.ReviewAccess(c.Request.Context(), user.ID, c.Param("teamId"), c.Param("requestId"), input.Accept); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ProjectHandler) RequestDeletion(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.RequestDeletion
	if !response.BindJSON(c, &input) {
		return
	}
	request, err := h.service.RequestDeletion(c.Request.Context(), user.ID, c.Param("projectId"), input.Message)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"request": request})
}

func (h *ProjectHandler) DeleteRequests(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	requests, err := h.service.DeleteRequests(c.Request.Context(), user.ID, c.Param("teamId"))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"requests": requests})
}

func (h *ProjectHandler) ReviewDeletion(c *gin.Context) {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		response.Unauthorized(c)
		return
	}
	var input model.ReviewRequest
	if !response.BindJSON(c, &input) {
		return
	}
	if err := h.service.ReviewDeletion(c.Request.Context(), user.ID, c.Param("teamId"), c.Param("requestId"), input.Accept); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func respondError(c *gin.Context, err error) {
	response.RespondError(c, response.StatusFor(err), err)
}
