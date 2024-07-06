package router

import (
	"net/http"

	"github.com/gin-contrib/pprof"
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

func (r *Router) RegisterMiddlewares(middlewares []interface{}) error {
	for _, middleware := range middlewares {
		if mdw, ok := middleware.(gin.HandlerFunc); ok {
			r.gin.Use(mdw)
		}
	}
	return nil
}

func (r *Router) RegisterPprof() {
	pprof.Register(r.gin)
}

func (r *Router) StartServer(port string) error {
	return r.gin.Run(":" + port)
}

func (r *Router) Http2H2CEnabled() {
	r.gin.UseH2C = true
}
