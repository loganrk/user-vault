package v1

import (
	"context"
	request "mayilon/internal/adapters/handler/http/v1/request/user"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/core/constant.go"
	"net/http"
)

func (h *handler) UserRegister(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserRegister()
	res := response.New()

	err := req.Parse(r)
	if err != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_REQUEST_INVALID, "invalid request parameters")
		res.Send(w)
		return
	}

	err = req.Validate()
	if err != nil {
		res.SetStatus(http.StatusUnprocessableEntity)
		res.SetError(ERROR_CODE_REQUEST_PARAMS_INVALID, err.Error())
		res.Send(w)
		return
	}

	userData, err := h.services.User.GetUserByUsername(ctx, req.Username)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}
	if userData.Id != 0 {
		res.SetStatus(http.StatusConflict)
		res.SetError(ERROR_CODE_USERNAME_NOT_AVAILABLE, "username already exists. try different username")
		res.Send(w)
		return
	}

	userid, err := h.services.User.CreateUser(ctx, req.Username, req.Password, req.Name)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	userData, err = h.services.User.GetUserByUserid(ctx, userid)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if userData.Id == 0 {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if userData.Status == constant.USER_STATUS_PENDING {
		tokenId, activationToken, err := h.services.User.CreateActivationToken(ctx, userData.Id)
		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		if tokenId != 0 && activationToken != "" {
			activationLink := h.services.User.GetActivationLink(tokenId, activationToken)
			if activationLink != "" {
				template, err := h.services.User.GetActivationEmailTemplate(ctx, userData.Name, activationLink)
				if err != nil {
					res.SetStatus(http.StatusInternalServerError)
					res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
					res.Send(w)
					return
				}

				if template != "" {
					err := h.services.User.SendActivation(ctx, userData.Username, template)
					if err != nil {
						res.SetStatus(http.StatusInternalServerError)
						res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
						res.Send(w)
						return
					}
					resData := "account created successfuly. please check your email for activate account"
					res.SetData(resData)
					res.Send(w)
					return
				}
			}

		}
	}

	resData := "account created successfuly"
	res.SetData(resData)
	res.Send(w)
}
