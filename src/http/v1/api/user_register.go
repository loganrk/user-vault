package api

import (
	"context"
	"mayilon/src/http/v1/request"
	"mayilon/src/http/v1/response"
	"mayilon/src/types"
	"net/http"
)

func (a *Api) UserRegister(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserRegister()
	res := response.New()

	err := req.Parse(r)
	if err != nil {
		// TODO log
		res.SetError("invalid request parameters")
		res.Send(w)
		return
	}

	result := req.Validate()
	if result != "" {
		res.SetError(result)
		res.Send(w)
		return
	}

	userData := a.Services.User.GetUserByUsername(ctx, req.Username)
	if userData.Id != 0 {
		res.SetError("username already exists. try different username")
		res.Send(w)
		return
	}

	userid := a.Services.User.CreateUser(ctx, req.Username, req.Password, req.Name)
	if userData.Id == 0 {
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	userData = a.Services.User.GetUserByUserid(ctx, userid)

	if userData.Id != 0 {
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if userData.Status == types.USER_STATUS_PENDING {
		tokenId, activationToken := a.Services.User.CreateActivationToken(ctx, userData.Id)
		if tokenId != 0 && activationToken != "" {
			activationLink := a.Services.User.GetActivationLink(tokenId, activationToken)
			if activationLink != "" {
				template := a.Services.User.GetActivationEmailTemplate(ctx, userData.Name, activationLink)
				if template != "" {
					emailStatus := a.Services.User.SendUserActivation(ctx, userData.Username, template)
					if emailStatus == types.EMAIL_STATUS_SUCCESS {
						resData := "account created successfuly. please check your email for activate account"
						res.SetData(resData)
						res.Send(w)
						return
					}
				}
			}

		}
	}

	resData := "account created successfuly"
	res.SetData(resData)
	res.Send(w)
}

func (a *Api) UserForgotPassword(w http.ResponseWriter, r *http.Request) {

}

func (a *Api) UserResetPassword(w http.ResponseWriter, r *http.Request) {

}
