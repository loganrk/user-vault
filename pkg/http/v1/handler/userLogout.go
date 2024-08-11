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

	err = req.Validate()
	if err != nil {
		res.SetStatus(http.StatusUnprocessableEntity)
		res.SetError(err.Error())
		res.Send(w)
		return
	}

	userid, expiresAt, err := h.authentication.GetRefreshTokenData(req.RefreshToken)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if userid == 0 {
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

	err = h.services.User.RevokedRefreshToken(ctx, userid, req.RefreshToken)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	resData := "logout successfully"
	res.SetData(resData)
	res.Send(w)
}
