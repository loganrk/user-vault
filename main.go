package main

import (
	"log"
	"mayilon/config"
	"mayilon/src/http/v1/api"
	"mayilon/src/lib/db"
	"mayilon/src/lib/router"
	"mayilon/src/service"
	userSrv "mayilon/src/service/user"
	userStore "mayilon/src/store/user"
)

func main() {

	appConfigIns, err := config.StartAppConfig("")
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

	userStoreIns := userStore.New(appConfigIns, dbIns)
	userSrvIns := userSrv.New(userStoreIns)

	svcList := service.List{
		User: userSrvIns,
	}

	apiIns := api.New(svcList)

	routerIns := router.New()

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

	port := appConfigIns.GetPort()
	routerIns.StartServer(port)
}
