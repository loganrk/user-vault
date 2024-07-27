package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type route struct {
	gin *gin.Engine
}

func New() *route {
	gin.DisableConsoleColor()
	return &route{
		gin: gin.Default(),
	}
}

func (r *route) RegisterRoute(method, path string, handlerFunc http.HandlerFunc) {
	r.gin.Handle(method, path, func(c *gin.Context) {
		handlerFunc(c.Writer, c.Request)
	})
}

func (r *route) StartServer(port string) error {
	return r.gin.Run(":" + port)
}

func (r *route) UseBefore(middlewares ...http.HandlerFunc) {
	for _, middleware := range middlewares {
		r.gin.Use(wrapHTTPHandlerFunc(middleware))
	}
}

func wrapHTTPHandlerFunc(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
		if c.Writer.Status() != http.StatusOK {
			c.Abort()
		}
		c.Next()
	}
}
