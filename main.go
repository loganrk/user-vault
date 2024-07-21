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

	appConfigIns, err := config.StartAppConfig(`C:\xampp\htdocs\pro\mayilon\config\yaml\app.yaml`)
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

	if appConfigIns.GetApiUserLoginEnabled() {
		userApiMethod, userApiRoute := appConfigIns.GetApiUserLoginProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserLogin)

	}

	if appConfigIns.GetApiUserRegisterEnabled() {
		userApiMethod, userApiRoute := appConfigIns.GetApiUserRegisterProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserRegister)
	}

	if appConfigIns.GetApiUserForgotPasswordEnabled() {
		userApiMethod, userApiRoute := appConfigIns.GetApiUserForgotPasswordProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserForgotPassword)
	}

	if appConfigIns.GetApiUserResetPasswordEnabled() {
		userApiMethod, userApiRoute := appConfigIns.GetApiUserResetPasswordProperties()
		routerIns.RegisterRoute(userApiMethod, userApiRoute, apiIns.UserResetPassword)
	}

	port := appConfigIns.GetAppPort()
	err3 := routerIns.StartServer(port)
	if err3 != nil {
		log.Println(err3)
		return
	}
}
