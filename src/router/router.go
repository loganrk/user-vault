package router

import (
	"errors"
	"fmt"
	"mayilon/config"
	"mayilon/src/store"

	"github.com/gin-gonic/gin"
)

func New(appConfigIns config.App, storeIns store.Store) error {

	gin.DisableConsoleColor()
	r := gin.New()

	enabled, route, method := storeIns.GetEndpointCategoryProperties()
	if enabled {
		err := setRoute(r, route, method, controller.Category)
		if err != nil {
			return err
		}
	}

	enabled, route, method = storeIns.GetEndpointProductProperties()
	if enabled {
		err := setRoute(r, route, method, controller.Product)
		if err != nil {
			return err
		}
	}
	return r.Run(storeIns.GetPort())
}

func setRoute(r *gin.Engine, route string, method string, callback func()) error {

	if method == "get" {
		r.GET("/"+route, func(c *gin.Context) {
			callback(c.Writer, c.Request)
		})
	} else if method == "post" {
		r.POST("/"+route, func(c *gin.Context) {
			callback(c.Writer, c.Request)
		})
	} else {
		return errors.New(fmt.Sprintf("invalid method for setup route endpoint. method = %s, route = %s", method, route))
	}

	return nil
}
