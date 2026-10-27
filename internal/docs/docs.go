package docs

import (
	"embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed openapi.yaml swagger.html
var files embed.FS

func RegisterRoutes(router *gin.Engine) {
	router.GET("/openapi.yaml", func(c *gin.Context) {
		c.Header("Content-Type", "application/yaml; charset=utf-8")
		c.FileFromFS("openapi.yaml", http.FS(files))
	})
	router.GET("/swagger", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.FileFromFS("swagger.html", http.FS(files))
	})
	router.GET("/swagger/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/swagger")
	})
}
