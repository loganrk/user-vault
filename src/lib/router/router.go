package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Router struct {
	gin *gin.Engine
}

func New() *Router {
	gin.DisableConsoleColor()
	return &Router{
		gin: gin.Default(),
	}
}

func (r *Router) RegisterRoute(method, path string, handlerFunc http.HandlerFunc) {
	r.gin.Handle(method, path, func(c *gin.Context) {
		handlerFunc(c.Writer, c.Request)
	})
}

func (r *Router) StartServer(port string) error {
	return r.gin.Run(":" + port)
}
