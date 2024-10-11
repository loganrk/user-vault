package v1

import (
	"context"
	"time"

	"mayilon/internal/adapters/handler/http/v1/request"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/port"

	"net/http"
)

func (h *handler) UserLogout(w http.ResponseWriter, r *http.Request) {

	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserLogout(r)

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

	userid, expiresAt, err := h.tokenEngineIns.GetRefreshTokenData(req.GetRefreshToken())
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

	err = h.usecases.User.RevokedRefreshToken(ctx, userid, req.GetRefreshToken())
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	resData := port.UserLogoutClientResponse{
		Message: "logout successfully",
	}
	res.SetData(resData)
	res.Send(w)
}
