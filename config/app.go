package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

type App interface {
	GetPort() string
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

type Table interface {
	GetPrefix() string
	GetUser() string
	GetUserLoginAttemp() string
}
type User interface {
	GetMaxLoginAttempt() int
	GetLoginAttemptSessionPeriod() int
	GetPasswordHashCost() int
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

func (c app) GetMiddlewareAuthorizationProperties() (bool, string) {
	authorization := c.Middleware.Authorization
	return authorization.Enabled, authorization.Token
}
func (c app) GetMiddlewareAuthenticationProperties() (string, int) {
	authentication := c.Middleware.Authentication
	return authentication.SecretKey, authentication.TokenExpiry
}

/* start of config-store */
func (c app) GetStoreDatabaseProperties() (string, string, string, string, string) {
	database := c.Store.Database

	return database.Host, database.Port, database.Username, database.Password, database.Name
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

func (c app) GetTable() Table {
	return c.Store.Database.Table
}

func (t table) GetPrefix() string {

	return t.Prefix
}

func (t table) GetUser() string {

	return t.User
}
func (t table) GetUserLoginAttemp() string {

	return t.UserLoginAttempt
}

func (c app) GetUser() User {

	return c.User
}

func (c user) GetMaxLoginAttempt() int {

	return c.MaxLoginAttempt
}

func (c user) GetLoginAttemptSessionPeriod() int {

	return c.LoginAttemptSessionPeriod
}
func (c user) GetPasswordHashCost() int {

	return c.PasswordHashCost
}
