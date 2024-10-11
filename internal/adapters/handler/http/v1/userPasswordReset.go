package v1

import (
	"context"
	"mayilon/internal/adapters/handler/http/v1/request"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/constant"
	"mayilon/internal/port"
	"net/http"
	"time"
)

func (h *handler) UserPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserResetPassword(r)
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
	tokenData, err := h.usecases.User.GetPasswordResetByToken(ctx, req.GetToken())
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

	userData, err := h.usecases.User.GetUserByUserid(ctx, tokenData.UserId)
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

	err = h.usecases.User.UpdatePassword(ctx, userData.Id, req.GetPassword(), userData.Salt)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}
	// TODO : need to automatied script when its fail
	err = h.usecases.User.UpdatedPasswordResetStatus(ctx, tokenData.Id, constant.USER_PASSWORD_RESET_STATUS_INACTIVE)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	resData := port.UserResetPasswordClientResponse{
		Message: "password has been reset successfully",
	}
	res.SetData(resData)
	res.Send(w)

}
