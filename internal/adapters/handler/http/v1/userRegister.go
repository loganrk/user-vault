package v1

import (
	"context"
	"mayilon/internal/adapters/handler/http/v1/request"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/constant"
	"mayilon/internal/port"
	"net/http"
)

func (h *handler) UserRegister(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserRegister(r)
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

	userData, err := h.usecases.User.GetUserByUsername(ctx, req.GetUsername())
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

	userid, err := h.usecases.User.CreateUser(ctx, req.GetUsername(), req.GetPassword(), req.GetName())
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	userData, err = h.usecases.User.GetUserByUserid(ctx, userid)
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
		tokenId, activationToken, err := h.usecases.User.CreateActivationToken(ctx, userData.Id)
		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		if tokenId != 0 && activationToken != "" {
			activationLink := h.usecases.User.GetActivationLink(tokenId, activationToken)
			if activationLink != "" {
				template, err := h.usecases.User.GetActivationEmailTemplate(ctx, userData.Name, activationLink)
				if err != nil {
					res.SetStatus(http.StatusInternalServerError)
					res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
					res.Send(w)
					return
				}

				if template != "" {
					err := h.usecases.User.SendActivation(ctx, userData.Username, template)
					if err != nil {
						res.SetStatus(http.StatusInternalServerError)
						res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
						res.Send(w)
						return
					}
					resData := port.UserRegisterClientResponse{
						Message: "account created successfuly. please check your email for activate account",
					}
					res.SetData(resData)
					res.Send(w)
					return
				}
			}

		}
	}

	resData := port.UserRegisterClientResponse{
		Message: "account created successfuly",
	}
	res.SetData(resData)
	res.Send(w)
}
