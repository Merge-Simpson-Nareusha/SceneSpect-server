package handler

import (
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/media"
	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/global/response"
)

type Handler struct{ store *media.Store }

func NewHandler(store *media.Store) *Handler { return &Handler{store: store} }

func (h *Handler) Register(router *gin.Engine, api *gin.RouterGroup, auth gin.HandlerFunc) {
	api.POST("/media/images", auth, h.Upload)
	router.GET("/media/:filename", h.Serve)
}

func (h *Handler) Upload(c *gin.Context) {
	const multipartOverhead = 512 << 10
	maxBody := h.store.MaxBytes() + multipartOverhead
	if c.Request.ContentLength > maxBody {
		response.RespondError(c, http.StatusRequestEntityTooLarge, response.ErrInvalid)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBody)
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrInvalid)
		return
	}
	defer file.Close()
	imageBytes, err := io.ReadAll(io.LimitReader(file, h.store.MaxBytes()+1))
	if err != nil || int64(len(imageBytes)) > h.store.MaxBytes() {
		response.RespondError(c, http.StatusRequestEntityTooLarge, response.ErrInvalid)
		return
	}
	imageURL, err := h.store.Save(imageBytes)
	if err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrInvalid)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"url": imageURL})
}

func (h *Handler) Serve(c *gin.Context) {
	filename := c.Param("filename")
	path, err := h.store.Path(filename)
	if err != nil {
		http.NotFound(c.Writer, c.Request)
		return
	}
	if _, err = os.Stat(path); err != nil {
		http.NotFound(c.Writer, c.Request)
		return
	}
	if strings.HasSuffix(filename, ".png") {
		c.Header("Content-Type", "image/png")
	} else {
		c.Header("Content-Type", "image/jpeg")
	}
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Header("X-Content-Type-Options", "nosniff")
	http.ServeFile(c.Writer, c.Request, path)
}
