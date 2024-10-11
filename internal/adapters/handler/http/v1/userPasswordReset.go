package v1

import (
	"context"
	request "mayilon/internal/adapters/handler/http/v1/request/user"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/core/constant"
	"net/http"
	"time"
)

func (h *handler) UserPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserResetPassword()
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
	tokenData, err := h.services.User.GetPasswordResetByToken(ctx, req.Token)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if tokenData.Id == 0 {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_INCORRECT, "incorrect link")
		res.Send(w)
		return
	}

	if tokenData.Status != constant.USER_PASSWORD_RESET_STATUS_ACTIVE {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_ALREADY_USED, "link already used")
		res.Send(w)
		return
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_EXPIRED, "link expired")
		res.Send(w)
		return
	}

	userData, err := h.services.User.GetUserByUserid(ctx, tokenData.UserId)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if userData.Status != constant.USER_STATUS_ACTIVE {

		res.SetStatus(http.StatusForbidden)
		if userData.Status == constant.USER_STATUS_INACTIVE {
			res.SetError(ERROR_CODE_ACCOUNT_INACTIVE, "your account is currently inactive")
		} else if userData.Status == constant.USER_STATUS_PENDING {
			res.SetError(ERROR_CODE_ACCOUNT_PENDING, "your account verification is pending")
		} else {
			res.SetError(ERROR_CODE_ACCOUNT_BANNED, "your account has been banned")
		}

		res.Send(w)
		return
	}

	err = h.services.User.UpdatePassword(ctx, userData.Id, req.Password, userData.Salt)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}
	// TODO : need to automatied script when its fail
	err = h.services.User.UpdatedPasswordResetStatus(ctx, tokenData.Id, constant.USER_PASSWORD_RESET_STATUS_INACTIVE)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	resData := "password has been reset successfully"
	res.SetData(resData)
	res.Send(w)

}
