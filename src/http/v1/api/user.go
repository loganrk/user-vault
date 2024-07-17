package api

import (
	"context"
	"mayilon/src/types"
	"net/http"
)

func (a *Api) UserLogin(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	userId := a.Services.User.GetUserIdFromUsername(ctx, "username")
	if userId != 0 {

	}

	attemptStatus := a.Services.User.CheckLoginAttempt(ctx, userId)
	if attemptStatus == types.LOGIN_ATTEMPT_NOT_PROCEED {

	} else if attemptStatus == types.LOGIN_ATTEMPT_MAX_REACHED {

	}

	userData := a.Services.User.GetUserDataFromUsernameAndPassword(ctx, "username", "password")
	if userData.Id != 0 {

	}

}

func (a *Api) UserRegister(w http.ResponseWriter, r *http.Request) {

}

func (a *Api) UserForgotPassword(w http.ResponseWriter, r *http.Request) {

}

func (a *Api) UserResetPassword(w http.ResponseWriter, r *http.Request) {

}
