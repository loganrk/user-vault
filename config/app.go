package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

type App interface {
	GetAppName() string
	GetAppPort() string
	GetMiddlewareAuthorizationProperties() (bool, string)
	GetMiddlewareAuthenticationProperties() (string, int)
	GetStoreDatabaseProperties() (string, string, string, string, string)
	GetStoreCacheHeapProperties() (bool, int)
	GetApiUserLoginEnabled() bool
	GetApiUserLoginProperties() (string, string)
	GetApiUserRegisterEnabled() bool
	GetApiUserRegisterProperties() (string, string)
	GetApiUserForgotPasswordEnabled() bool
	GetApiUserForgotPasswordProperties() (string, string)
	GetApiUserResetPasswordEnabled() bool
	GetApiUserResetPasswordProperties() (string, string)
	GetTable() Table
	GetUser() User
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

func (a app) GetAppName() string {
	return a.Application.Name
}

func (a app) GetAppPort() string {
	return a.Application.Port
}

func (a app) GetMiddlewareAuthorizationProperties() (bool, string) {
	authorization := a.Middleware.Authorization
	return authorization.Enabled, authorization.Token
}
func (a app) GetMiddlewareAuthenticationProperties() (string, int) {
	authentication := a.Middleware.Authentication
	return authentication.SecretKey, authentication.TokenExpiry
}

/* start of config-store */
func (a app) GetStoreDatabaseProperties() (string, string, string, string, string) {
	database := a.Store.Database

	return database.Host, database.Port, database.Username, database.Password, database.Name
}

func (a app) GetStoreCacheHeapProperties() (bool, int) {
	heapCache := a.Store.Cache.Heap

	return heapCache.Enabled, heapCache.Expiry
}

/* start of config-api */
func (a app) GetApiUserLoginEnabled() bool {

	return a.Api.UserLogin.Enabled
}

func (a app) GetApiUserLoginProperties() (string, string) {
	api := a.Api.UserLogin

	return api.Method, api.Route
}

func (a app) GetApiUserRegisterEnabled() bool {

	return a.Api.UserRegister.Enabled
}

func (a app) GetApiUserRegisterProperties() (string, string) {
	api := a.Api.UserRegister

	return api.Method, api.Route
}

func (a app) GetApiUserForgotPasswordEnabled() bool {

	return a.Api.UserForgotPassword.Enabled
}

func (a app) GetApiUserForgotPasswordProperties() (string, string) {
	api := a.Api.UserForgotPassword

	return api.Method, api.Route
}

func (a app) GetApiUserResetPasswordEnabled() bool {
	return a.Api.UserResetPassword.Enabled
}
func (a app) GetApiUserResetPasswordProperties() (string, string) {
	api := a.Api.UserResetPassword

	return api.Method, api.Route
}

func (a app) GetUser() User {
	return a.User
}

func (a app) GetTable() Table {
	return a.Store.Database.Table
}
