package handler

import (
	"context"
	request "mayilon/pkg/http/v1/request/user"
	"mayilon/pkg/http/v1/response"
	"mayilon/pkg/types"
	"net/http"
)

func (h *Handler) UserRegister(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserRegister()
	res := response.New()

	err := req.Parse(r)
	if err != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid request parameters")
		res.Send(w)
		return
	}

	result := req.Validate()
	if result != "" {
		res.SetStatus(http.StatusUnprocessableEntity)
		res.SetError(result)
		res.Send(w)
		return
	}

	userData := h.services.User.GetUserByUsername(ctx, req.Username)
	if userData.Id != 0 {
		res.SetStatus(http.StatusConflict)
		res.SetError("username already exists. try different username")
		res.Send(w)
		return
	}

	userid := h.services.User.CreateUser(ctx, req.Username, req.Password, req.Name)
	if userid == 0 {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	userData = h.services.User.GetUserByUserid(ctx, userid)
	if userData.Id == 0 {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if userData.Status == types.USER_STATUS_PENDING {
		tokenId, activationToken := h.services.User.CreateActivationToken(ctx, userData.Id)
		if tokenId != 0 && activationToken != "" {
			activationLink := h.services.User.GetActivationLink(tokenId, activationToken)
			if activationLink != "" {
				template := h.services.User.GetActivationEmailTemplate(ctx, userData.Name, activationLink)
				if template != "" {
					emailStatus := h.services.User.SendActivation(ctx, userData.Username, template)
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
