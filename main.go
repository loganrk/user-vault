package main

import (
	"log"
	"mayilon/pkg/config"
	"mayilon/pkg/http/v1/api"
	chipper "mayilon/pkg/lib/chipper"
	"mayilon/pkg/lib/db"
	"mayilon/pkg/lib/router"
	authnMiddleware "mayilon/pkg/middleware/authn"
	authzMiddleware "mayilon/pkg/middleware/authz"

	"mayilon/pkg/service"
	userSrv "mayilon/pkg/service/user"
	userStore "mayilon/pkg/store/user"
)

func main() {

	appConfigIns, err := config.StartConfig(`C:\xampp\htdocs\pro\mayilon\config\yaml\`, config.File{
		Name: "app_config",
		Ext:  "yaml",
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
	authnMiddlewareIns := authnMiddleware.New(chipperCryptoKey, authnMiddlewareTokenExpiry, chipperIns)

	authzMiddlewareEnabled, authzMiddlewareToken := appConfigIns.GetMiddlewareAuthorizationProperties()
	if authzMiddlewareEnabled {
		authzMiddlewareIns := authzMiddleware.New(authzMiddlewareToken)
		routerIns.UseBefore(authzMiddlewareIns.Use())
	}

	apiIns := api.New(svcList, authnMiddlewareIns)
	apiConfigIns := appConfigIns.GetApi()

	if apiConfigIns.GetUserLoginEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserLoginProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserLogin)
	}

	if apiConfigIns.GetUserRegisterEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserRegisterProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserRegister)
	}

	if apiConfigIns.GetUserActivationEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserActivationProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserActivation)
	}

	if apiConfigIns.GetUserForgotPasswordEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserForgotPasswordProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserForgotPassword)
	}

	if apiConfigIns.GetUserPasswordResetEnabled() {
		userApiMethod, userApiRoute := apiConfigIns.GetUserPasswordResetProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserPasswordReset)
	}

	port := appConfigIns.GetAppPort()
	err3 := routerIns.StartServer(port)
	if err3 != nil {
		log.Println(err3)
		return
	}
}
