package router

import (
	"mayilon/src/lib/router/gin"
	"net/http"
)

type Router interface {
	RegisterRoute(method, path string, handlerFunc http.HandlerFunc)
	StartServer(port string) error
	UseBefore(middlewares ...http.HandlerFunc)
}

func New() Router {
	return gin.New()
}
