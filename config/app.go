package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

type App interface {
	GetPort() string
	GetMiddlewareAuthProperties() (bool, string)
	GetStoreDatabaseProperties() (string, string, string, string, string)
	GetStoreDatabaseTableUser() string
	GetStoreCacheHeapProperties() (bool, int)
	GetApiUserLoginEnabled() bool
	GetApiUserLoginProperties() (string, string)
	GetApiUserRegisterEnabled() bool
	GetApiUserRegisterProperties() (string, string)
	GetApiUserForgotPasswordEnabled() bool
	GetApiUserForgotPasswordProperties() (string, string)
	GetApiUserResetPasswordEnabled() bool
	GetApiUserResetPasswordProperties() (string, string)
}

func StartAppConfig(path string) (App, error) {
	var appConfig app

	configFile, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("error reading config file")
	}

	if err := yaml.Unmarshal(configFile, &appConfig); err != nil {
		return nil, errors.New("error unmarshalling config. error: " + err.Error())
	}

	return appConfig, nil
}

func (c app) GetPort() string {
	return c.Port
}

func (c app) GetMiddlewareAuthProperties() (bool, string) {
	auth := c.Middleware.Auth
	return auth.Enabled, auth.Token
}

/* start of config-store */
func (c app) GetStoreDatabaseProperties() (string, string, string, string, string) {
	database := c.Store.Database

	return database.Host, database.Port, database.Username, database.Password, database.Name
}

func (c app) GetStoreDatabaseTableUser() string {

	return c.Store.Database.Tables.User
}

func (c app) GetStoreCacheHeapProperties() (bool, int) {
	heapCache := c.Store.Cache.Heap

	return heapCache.Enabled, heapCache.Expiry
}

/* start of config-api */
func (c app) GetApiUserLoginEnabled() bool {

	return c.Api.UserLogin.Enabled
}

func (c app) GetApiUserLoginProperties() (string, string) {
	api := c.Api.UserLogin

	return api.Method, api.Route
}

func (c app) GetApiUserRegisterEnabled() bool {

	return c.Api.UserRegister.Enabled
}

func (c app) GetApiUserRegisterProperties() (string, string) {
	api := c.Api.UserRegister

	return api.Method, api.Route
}

func (c app) GetApiUserForgotPasswordEnabled() bool {

	return c.Api.UserForgotPassword.Enabled
}

func (c app) GetApiUserForgotPasswordProperties() (string, string) {
	api := c.Api.UserForgotPassword

	return api.Method, api.Route
}

func (c app) GetApiUserResetPasswordEnabled() bool {
	return c.Api.UserResetPassword.Enabled
}
func (c app) GetApiUserResetPasswordProperties() (string, string) {
	api := c.Api.UserResetPassword

	return api.Method, api.Route
}
