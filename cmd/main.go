package main

import (
	"context"
	"log"
	"mayilon/config"
	"mayilon/internal/domain"
	"mayilon/internal/port"

	cipherAes "mayilon/internal/adapters/cipher/aes"
	handler "mayilon/internal/adapters/handler/http/v1"
	loggerZap "mayilon/internal/adapters/logger/zapLogger"
	middlewareAuth "mayilon/internal/adapters/middleware/auth"
	repositoryMysql "mayilon/internal/adapters/repository/mysql"
	routerGin "mayilon/internal/adapters/router/gin"
	tokenEngineJwt "mayilon/internal/adapters/tokenEngine/jwt"

	userSrv "mayilon/internal/usecase/user"
)

const (
	CONFIG_FILE_PATH = ``
	CONFIG_FILE_NAME = `app_config`
	CONFIG_FILE_TYPE = `yaml`
)

func main() {
	/* get the config instance */
	appConfigIns, err := config.StartConfig(CONFIG_FILE_PATH, config.File{
		Name: CONFIG_FILE_NAME,
		Ext:  CONFIG_FILE_TYPE,
	})
	if err != nil {
		log.Println(err)
		return
	}

	/* get the logger instance */
	loggerIns, err := getLogger(appConfigIns.GetLogger())
	if err != nil {
		log.Println(err)
		return
	}

	/* get the database instance */
	mysqlIns, err := getDatabase(appConfigIns)
	if err != nil {
		log.Println(err)
		return
	}
	mysqlIns.AutoMigrate()

	/* get the user usecase instance */
	userSrvIns := userSrv.New(loggerIns, mysqlIns, appConfigIns.GetAppName(), appConfigIns.GetUser())

	svcList := domain.List{
		User: userSrvIns,
	}

	/* get the router instance */
	routerIns := getRouter(appConfigIns, loggerIns, svcList)

	/* start the usecase */
	port := appConfigIns.GetAppPort()
	loggerIns.Infow(context.Background(), "app started", "port", port)
	loggerIns.Sync(context.Background())

	err = routerIns.StartServer(port)
	if err != nil {
		loggerIns.Errorw(context.Background(), "app stoped", "port", port, "error", err)
		loggerIns.Sync(context.Background())
		return
	}

	loggerIns.Infow(context.Background(), "app stoped", "port", port, "error", nil)
	loggerIns.Sync(context.Background())
}

func getLogger(logConfigIns config.Logger) (port.Logger, error) {
	loggerConfig := loggerZap.Config{
		Level:           logConfigIns.GetLoggerLevel(),
		Encoding:        logConfigIns.GetLoggerEncodingMethod(),
		EncodingCaller:  logConfigIns.GetLoggerEncodingCaller(),
		OutputPath:      logConfigIns.GetLoggerPath(),
		ErrorOutputPath: logConfigIns.GetLoggerErrorPath(),
	}
	return loggerZap.New(loggerConfig)
}

func getDatabase(appConfigIns config.App) (port.RepositoryMySQL, error) {
	cipherCryptoKey := appConfigIns.GetCipherCryptoKey()
	cipherIns := cipherAes.New(cipherCryptoKey)

	encryptDbHost, encryptDbPort, encryptDbUsename, encryptDbPasword, dbName, prefix := appConfigIns.GetStoreDatabaseProperties()

	decryptDbHost, decryptErr := cipherIns.Decrypt(encryptDbHost)
	if decryptErr != nil {
		return nil, decryptErr
	}

	decryptdbPort, decryptErr := cipherIns.Decrypt(encryptDbPort)
	if decryptErr != nil {
		return nil, decryptErr
	}

	decryptDbUsename, decryptErr := cipherIns.Decrypt(encryptDbUsename)
	if decryptErr != nil {
		return nil, decryptErr
	}

	decryptDbPasword, decryptErr := cipherIns.Decrypt(encryptDbPasword)
	if decryptErr != nil {
		return nil, decryptErr
	}

	return repositoryMysql.New(decryptDbHost, decryptdbPort, decryptDbUsename, decryptDbPasword, dbName, prefix)

}

func getRouter(appConfigIns config.App, loggerIns port.Logger, svcList domain.List) port.Router {
	cipherCryptoKey := appConfigIns.GetCipherCryptoKey()
	cipherIns := cipherAes.New(cipherCryptoKey)
	apiKeys := appConfigIns.GetMiddlewareApiKeys()

	accessTokenExpiry := appConfigIns.GetMiddlewareAccessTokenExpiry()
	refreshTokenExpiry := appConfigIns.GetMiddlewareRefreshTokenExpiry()

	tokenEngineIns := tokenEngineJwt.New(cipherCryptoKey, accessTokenExpiry, refreshTokenExpiry, cipherIns)

	middlewareAuthIns := middlewareAuth.New(apiKeys, tokenEngineIns)

	handlerIns := handler.New(loggerIns, tokenEngineIns, svcList)
	apiConfigIns := appConfigIns.GetApi()

	routerIns := routerGin.New()
	generalGr := routerIns.NewGroup("")
	generalGr.UseBefore(middlewareAuthIns.ValidateApiKey())

	if apiConfigIns.GetUserLoginEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserLoginProperties()
		generalGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserLogin)
	}

	if apiConfigIns.GetUserRegisterEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserRegisterProperties()
		generalGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserRegister)
	}

	if apiConfigIns.GetUserActivationEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserActivationProperties()
		generalGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserActivation)
	}

	if apiConfigIns.GetUserResendActivationEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserResendActivationProperties()
		generalGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserResendActivation)
	}

	if apiConfigIns.GetUserForgotPasswordEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserForgotPasswordProperties()
		generalGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserForgotPassword)
	}

	if apiConfigIns.GetUserPasswordResetEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserPasswordResetProperties()
		generalGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserPasswordReset)
	}

	if apiConfigIns.GetUserRefreshTokenValidateEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserRefreshTokenValidateProperties()
		generalGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserRefreshTokenValidate)
	}

	accessTokenGr := routerIns.NewGroup("")
	accessTokenGr.UseBefore(middlewareAuthIns.ValidateAccessToken())
	if apiConfigIns.GetUserLogoutEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserLogoutProperties()
		accessTokenGr.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserLogout)
	}

	return routerIns
}
