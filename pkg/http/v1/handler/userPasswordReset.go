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

	result := req.Validate()
	if result != "" {
		res.SetStatus(http.StatusUnprocessableEntity)
		res.SetError(result)
		res.Send(w)
		return
	}
	tokenData := h.services.User.GetPasswordResetByToken(ctx, req.Token)
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

	userData := h.services.User.GetUserByUserid(ctx, tokenData.UserId)

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

	result2 := h.services.User.UpdatePassword(ctx, userData.Id, req.Password, userData.Salt)
	if !result2 {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	// TODO : need to automatied script when its fail
	h.services.User.UpdatedPasswordResetStatus(ctx, tokenData.Id, types.USER_PASSWORD_RESET_STATUS_INACTIVE)

	resData := "password has been reset successfully"
	res.SetData(resData)
	res.Send(w)

}
