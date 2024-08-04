package main

import (
	"log"
	"mayilon/pkg/config"
	"mayilon/pkg/http/v1/handler"
	"mayilon/pkg/middleware"

	"github.com/loganrk/go-db"
	"github.com/loganrk/go-router"

	chipper "github.com/loganrk/go-chipper"

	"mayilon/pkg/service"
	userSrv "mayilon/pkg/service/user"
	userStore "mayilon/pkg/store/user"
)

const (
	CONFIG_FILE_PATH = ``
	CONFIG_FILE_NAME = `app_config`
	CONFIG_FILE_TYPE = `yaml`
)

func main() {

	appConfigIns, err := config.StartConfig(CONFIG_FILE_PATH, config.File{
		Name: CONFIG_FILE_NAME,
		Ext:  CONFIG_FILE_TYPE,
	})

	if err != nil {
		log.Println(err)
		return
	}

	chipperCryptoKey := appConfigIns.GetChipperCryptoKey()
	chipperIns := chipper.New(chipperCryptoKey)

	encryptDbHost, encryptDbPort, encryptDbUsename, encryptDbPasword, dbName := appConfigIns.GetStoreDatabaseProperties()

	decryptDbHost, decryptErr := chipperIns.Decrypt(encryptDbHost)
	if decryptErr != nil {
		log.Println(decryptErr)
		return
	}

	decryptdbPort, decryptErr := chipperIns.Decrypt(encryptDbPort)
	if decryptErr != nil {
		log.Println(decryptErr)
		return
	}

	decryptDbUsename, decryptErr := chipperIns.Decrypt(encryptDbUsename)
	if decryptErr != nil {
		log.Println(decryptErr)
		return
	}

	decryptDbPasword, decryptErr := chipperIns.Decrypt(encryptDbPasword)
	if decryptErr != nil {
		log.Println(decryptErr)
		return
	}

	dbIns, err2 := db.New(db.Config{
		Host:     decryptDbHost,
		Port:     decryptdbPort,
		Username: decryptDbUsename,
		Password: decryptDbPasword,
		Name:     dbName,
	})

	if err2 != nil {
		log.Println(err2)
		return
	}

	userStoreIns := userStore.New(appConfigIns.GetTable(), dbIns)
	userSrvIns := userSrv.New(userStoreIns, appConfigIns.GetAppName(), appConfigIns.GetUser())

	svcList := service.List{
		User: userSrvIns,
	}

	routerIns := router.New()

	authnMiddlewareTokenExpiry := appConfigIns.GetMiddlewareAuthenticationProperties()
	authnMiddlewareIns := middleware.NewAuthn(chipperCryptoKey, authnMiddlewareTokenExpiry, chipperIns)

	authzMiddlewareEnabled, authzMiddlewareToken := appConfigIns.GetMiddlewareAuthorizationProperties()
	if authzMiddlewareEnabled {
		authzMiddlewareIns := middleware.NewAuthz(authzMiddlewareToken)
		routerIns.UseBefore(authzMiddlewareIns.Use())
	}

	handlerIns := handler.New(svcList, authnMiddlewareIns)
	apiConfigIns := appConfigIns.GetApi()

	if apiConfigIns.GetUserLoginEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserLoginProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserLogin)
	}

	if apiConfigIns.GetUserRegisterEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserRegisterProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserRegister)
	}

	if apiConfigIns.GetUserActivationEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserActivationProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserActivation)
	}

	if apiConfigIns.GetUserResendActivationEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserResendActivationProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserResendActivation)
	}

	if apiConfigIns.GetUserForgotPasswordEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserForgotPasswordProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserForgotPassword)
	}

	if apiConfigIns.GetUserPasswordResetEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserPasswordResetProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, handlerIns.UserPasswordReset)
	}

	port := appConfigIns.GetAppPort()
	err3 := routerIns.StartServer(port)
	if err3 != nil {
		log.Println(err3)
		return
	}
}
