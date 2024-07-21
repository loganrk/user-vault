package main

import (
	"log"
	"mayilon/config"
	"mayilon/src/http/v1/api"
	"mayilon/src/lib/db"
	"mayilon/src/lib/router"
	authnMiddleware "mayilon/src/middleware/authn"
	authzMiddleware "mayilon/src/middleware/authz"

	"mayilon/src/service"
	userSrv "mayilon/src/service/user"
	userStore "mayilon/src/store/user"
)

func main() {

	appConfigIns, err := config.StartAppConfig(``)
	if err != nil {
		log.Println(err)
		return
	}

	dbHost, dbPort, dbUsename, dbPasword, dbName := appConfigIns.GetStoreDatabaseProperties()
	dbIns, err2 := db.New(db.Config{
		Host:     dbHost,
		Port:     dbPort,
		Username: dbUsename,
		Password: dbPasword,
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

	authnMiddlewareSecretKey, authnMiddlewareTokenExpiry := appConfigIns.GetMiddlewareAuthenticationProperties()
	authnMiddlewareIns := authnMiddleware.New(authnMiddlewareSecretKey, authnMiddlewareTokenExpiry)

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
