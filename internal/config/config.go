package config

import (
	"fmt"
	"os"
	"strings"

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
	GetStoreDatabaseProperties() (string, string, string, string, string, string)
	GetLogger() Logger
	GetKafka() Kafka
	GetUser() User
	GetJWTToken() Jwt
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

	overrideFromEnv(&appConfig)

	return appConfig, nil
}

func overrideFromEnv(appConfig *app) {

	if v := os.Getenv("KAFKA_BROKERS"); v != "" {
		appConfig.Kafka.Brokers = strings.Split(v, ",")
	}

	if v := os.Getenv("DB_HOST"); v != "" {
		appConfig.Store.Database.Host = v
	}

	if v := os.Getenv("DB_PORT"); v != "" {
		appConfig.Store.Database.Port = v
	}

	if v := os.Getenv("DB_USERNAME"); v != "" {
		appConfig.Store.Database.Username = v
	}

	if v := os.Getenv("DB_PASSWORD"); v != "" {
		appConfig.Store.Database.Password = v
	}

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

/* start of config-store */
func (a app) GetStoreDatabaseProperties() (string, string, string, string, string, string) {
	database := a.Store.Database

	return database.Host, database.Port, database.Username, database.Password, database.Name, database.Prefix
}

func (a app) GetUser() User {
	return a.User
}

func (a app) GetJWTToken() Jwt {
	return a.Token.JWT
}

func (a app) GetKafka() Kafka {
	return a.Kafka
}
