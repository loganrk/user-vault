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
	GetMiddlewareAuthorizationProperties() (bool, string)
	GetMiddlewareAuthenticationProperties() int
	GetStoreDatabaseProperties() (string, string, string, string, string)
	GetStoreCacheHeapProperties() (bool, int)
	GetApi() Api
	GetTable() Table
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

func (a app) GetAppName() string {
	return a.Application.Name
}

func (a app) GetAppPort() string {
	return a.Application.Port
}

func (a app) GetCipherCryptoKey() string {
	return a.Cipher.CryptoKey
}

func (a app) GetMiddlewareAuthorizationProperties() (bool, string) {
	authorization := a.Middleware.Authorization
	return authorization.Enabled, authorization.Token
}

func (a app) GetMiddlewareAuthenticationProperties() int {
	authentication := a.Middleware.Authentication
	return authentication.TokenExpiry
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

func (a app) GetApi() Api {
	return a.Api
}

func (a app) GetUser() User {
	return a.User
}

func (a app) GetTable() Table {
	return a.Store.Database.Table
}
