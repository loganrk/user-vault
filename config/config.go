package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type File struct {
	Name string
	Ext  string
}

type App interface {
	GetAppName() string
	GetAppPort() string
	GetCipherCryptoKey() string
	GetMiddlewareApiKeys() []string
	GetMiddlewareAccessTokenExpiry() int
	GetMiddlewareRefreshTokenExpiry() int

	GetStoreDatabaseProperties() (string, string, string, string, string, string)
	GetStoreCacheHeapProperties() (bool, int)
	GetLogger() Logger
	GetApi() Api
	GetUser() User
}

func StartConfig(path string, file File) (App, error) {
	var appConfig app

	var viperIns = viper.New()

	viperIns.AddConfigPath(path)
	viperIns.SetConfigName(file.Name)
	viperIns.AddConfigPath(".")
	viperIns.SetConfigType(file.Ext)

	if err := viperIns.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	err := viperIns.Unmarshal(&appConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %v", err)
	}

	return appConfig, nil
}

func (a app) GetLogger() Logger {
	return a.Logger
}

func (a app) GetAppName() string {
	return a.Application.Name
}

func (a app) GetAppPort() string {
	return a.Application.Port
}

func (a app) GetCipherCryptoKey() string {
	return a.Cipher.CryptoKey
}

func (a app) GetMiddlewareApiKeys() []string {
	return a.Middleware.Keys
}

func (a app) GetMiddlewareAccessTokenExpiry() int {
	return a.Middleware.AccessToken.Expiry
}

func (a app) GetMiddlewareRefreshTokenExpiry() int {
	return a.Middleware.RefreshToken.Expiry
}

/* start of config-store */
func (a app) GetStoreDatabaseProperties() (string, string, string, string, string, string) {
	database := a.Store.Database

	return database.Host, database.Port, database.Username, database.Password, database.Name, database.Prefix
}

func (a app) GetStoreCacheHeapProperties() (bool, int) {
	heapCache := a.Store.Cache.Heap

	return heapCache.Enabled, heapCache.Expiry
}

func (a app) GetApi() Api {
	return a.Api
}

func (a app) GetUser() User {
	return a.User
}
