package handler

import (
	"context"
	"time"

	request "mayilon/pkg/http/v1/request/user"
	"mayilon/pkg/http/v1/response"

	"net/http"
)

func (h *Handler) UserLogout(w http.ResponseWriter, r *http.Request) {

	ctx := context.Background()

	req := request.NewUserLogout()
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

	userid, expiresAt, err := h.Authentication.GetRefreshTokenData(req.RefreshToken)

	if err != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid token")
		res.Send(w)
		return
	}

	if expiresAt.Before(time.Now()) {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("token is expired")
		res.Send(w)
		return
	}

	result2 := h.Services.User.RevokedRefreshToken(ctx, userid, req.RefreshToken)
	if !result2 {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	resData := "logout successfully"
	res.SetData(resData)
	res.Send(w)
}
