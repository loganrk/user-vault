package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type App interface {
	GetPort() string
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

	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var appConfig app
	err = yaml.Unmarshal(configFile, &appConfig)
	if err != nil {
		return nil, err
	}

	return appConfig, nil
}

func (c app) GetPort() string {

	return c.port
}

/* start of config-store */
func (c app) GetStoreDatabaseProperties() (string, string, string, string, string) {
	database := c.store.database

	return database.host, database.port, database.username, database.password, database.name
}

func (c app) GetStoreDatabaseTableUser() string {

	return c.store.database.tables.user
}

func (c app) GetStoreCacheHeapProperties() (bool, int) {
	heapCache := c.store.cache.heap

	return heapCache.enabled, heapCache.expiry
}

/* start of config-api */
func (c app) GetApiUserLoginEnabled() bool {

	return c.api.userLogin.enabled
}

func (c app) GetApiUserLoginProperties() (string, string) {
	api := c.api.userLogin

	return api.method, api.route
}

func (c app) GetApiUserRegisterEnabled() bool {

	return c.api.userRegister.enabled
}

func (c app) GetApiUserRegisterProperties() (string, string) {
	api := c.api.userRegister

	return api.method, api.route
}

func (c app) GetApiUserForgotPasswordEnabled() bool {

	return c.api.userForgotPassword.enabled
}

func (c app) GetApiUserForgotPasswordProperties() (string, string) {
	api := c.api.userForgotPassword

	return api.method, api.route
}

func (c app) GetApiUserResetPasswordEnabled() bool {
	return c.api.userResetPassword.enabled
}
func (c app) GetApiUserResetPasswordProperties() (string, string) {
	api := c.api.userResetPassword

	return api.method, api.route
}
