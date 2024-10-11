package v1

import (
	"context"
	"time"

	request "mayilon/internal/adapters/handler/http/v1/request/user"
	"mayilon/internal/adapters/handler/http/v1/response"

	"net/http"
)

func (h *handler) UserLogout(w http.ResponseWriter, r *http.Request) {

	ctx := context.Background()

	req := request.NewUserLogout()
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

	userid, expiresAt, err := h.tokenEngineIns.GetRefreshTokenData(req.RefreshToken)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if userid == 0 {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_INCORRECT, "incorrect token")
		res.Send(w)
		return
	}

	if expiresAt.Before(time.Now()) {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_EXPIRED, "token is expired")
		res.Send(w)
		return
	}

	err = h.services.User.RevokedRefreshToken(ctx, userid, req.RefreshToken)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	resData := "logout successfully"
	res.SetData(resData)
	res.Send(w)
}
