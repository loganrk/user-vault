package handler

import (
	"context"
	request "mayilon/pkg/http/v1/request/user"
	"mayilon/pkg/http/v1/response"
	"mayilon/pkg/types"
	"net/http"
	"time"
)

func (h *Handler) UserPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserResetPassword()
	res := response.New()

	err := req.Parse(r)
	if err != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid request parameters")
		res.Send(w)
		return
	}

	err = req.Validate()
	if err != nil {
		res.SetStatus(http.StatusUnprocessableEntity)
		res.SetError(err.Error())
		res.Send(w)
		return
	}
	tokenData, err := h.services.User.GetPasswordResetByToken(ctx, req.Token)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if tokenData.Id == 0 {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid token")
		res.Send(w)
		return
	}

	if tokenData.Status != types.USER_PASSWORD_RESET_STATUS_ACTIVE {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("activation token already used")
		res.Send(w)
		return
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("activation link expired")
		res.Send(w)
		return
	}

	userData, err := h.services.User.GetUserByUserid(ctx, tokenData.UserId)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if userData.Status != types.USER_STATUS_ACTIVE {

		res.SetStatus(http.StatusForbidden)
		if userData.Status == types.USER_STATUS_INACTIVE {
			res.SetError("your account is currently inactive")
		} else if userData.Status == types.USER_STATUS_PENDING {
			res.SetError("your account verification is pending")
		} else {
			res.SetError("your account has been banned")
		}

		res.Send(w)
		return
	}

	err = h.services.User.UpdatePassword(ctx, userData.Id, req.Password, userData.Salt)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}
	// TODO : need to automatied script when its fail
	err = h.services.User.UpdatedPasswordResetStatus(ctx, tokenData.Id, types.USER_PASSWORD_RESET_STATUS_INACTIVE)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	resData := "password has been reset successfully"
	res.SetData(resData)
	res.Send(w)

}
