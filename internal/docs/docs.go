package docs

import (
	"embed"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
)

//go:embed openapi.yaml swagger.html
var files embed.FS

var (
	openAPISpecJSON     []byte
	openAPISpecJSONErr  error
	openAPISpecJSONOnce sync.Once
)

func RegisterRoutes(router *gin.Engine) {
	router.GET("/openapi.yaml", func(c *gin.Context) {
		c.Header("Content-Type", "application/yaml; charset=utf-8")
		c.FileFromFS("openapi.yaml", http.FS(files))
	})
	router.GET("/v3/api-docs", serveOpenAPISpecJSON)
	router.GET("/swagger-ui/index.html", serveSwaggerUI)
	router.GET("/swagger-ui/", serveSwaggerUI)
	router.GET("/swagger-ui", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/swagger-ui/index.html")
	})
	router.GET("/swagger", serveSwaggerUI)
	router.GET("/swagger/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/swagger")
	})
}

func serveSwaggerUI(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.FileFromFS("swagger.html", http.FS(files))
}

func serveOpenAPISpecJSON(c *gin.Context) {
	openAPISpecJSONOnce.Do(func() {
		var yamlSpec []byte
		yamlSpec, openAPISpecJSONErr = files.ReadFile("openapi.yaml")
		if openAPISpecJSONErr != nil {
			return
		}
		openAPISpecJSON, openAPISpecJSONErr = yaml.YAMLToJSON(yamlSpec)
	})
	if openAPISpecJSONErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OpenAPI 명세를 불러오지 못했습니다"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", openAPISpecJSON)
}
