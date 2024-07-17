package router

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Router interface {
	RegisterRoute(method, path string, handlerFunc http.HandlerFunc)
	StartServer(port string) error
	Use(middlewares ...http.HandlerFunc)
}

type router struct {
	gin *gin.Engine
}

func New() Router {
	gin.DisableConsoleColor()
	return &router{
		gin: gin.Default(),
	}
}

func (r *router) RegisterRoute(method, path string, handlerFunc http.HandlerFunc) {
	fmt.Println(method, path, handlerFunc)
	r.gin.Handle(method, path, func(c *gin.Context) {
		handlerFunc(c.Writer, c.Request)
	})
}

func (r *router) StartServer(port string) error {
	return r.gin.Run(":" + port)
}

func (r *router) Use(middlewares ...http.HandlerFunc) {
	for _, middleware := range middlewares {
		r.gin.Use(wrapHTTPHandlerFunc(middleware))
	}
}

func wrapHTTPHandlerFunc(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h(c.Writer, c.Request)
		c.Next()
	}
}
