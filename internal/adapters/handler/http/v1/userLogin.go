package v1

import (
	"context"

	request "mayilon/internal/adapters/handler/http/v1/request/user"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/core/constant.go"

	"net/http"
)

func (h *handler) UserLogin(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserLogin()
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

	if userData.Id == 0 {
		res.SetStatus(http.StatusUnauthorized)
		res.SetError(ERROR_CODE_USERNAME_OR_PASSWORD_INCORRECT, "username or password is incorrect")
		res.Send(w)
		return
	}

	attemptStatus, err := h.services.User.CheckLoginFailedAttempt(ctx, userData.Id)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if attemptStatus == constant.LOGIN_ATTEMPT_MAX_REACHED {
		res.SetStatus(http.StatusTooManyRequests)
		res.SetError(ERROR_CODE_MAX_ATTEMPT_REACHED, "max login attempt reached. please try after sometime")
		res.Send(w)
		return

	}

	passwordMatch, err := h.services.User.CheckPassword(ctx, req.Password, userData.Password, userData.Salt)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if !passwordMatch {
		loginAttempId, err := h.services.User.CreateLoginAttempt(ctx, userData.Id, false)

		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		if loginAttempId == 0 {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		res.SetStatus(http.StatusUnauthorized)
		res.SetError(ERROR_CODE_USERNAME_OR_PASSWORD_INCORRECT, "username or password is incorrect")
		res.Send(w)
		return
	} else {
		loginAttempId, err := h.services.User.CreateLoginAttempt(ctx, userData.Id, true)
		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		if loginAttempId == 0 {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}
	}
	userData, err = h.services.User.GetUserByUserid(ctx, userData.Id)
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

	var accessToken, refreshTokenType, refreshToken string

	accessToken, err = h.tokenEngineIns.CreateAccessToken(userData.Id, userData.Username, userData.Name)

	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if h.services.User.RefreshTokenEnabled() {

		if h.services.User.RefreshTokenRotationEnabled() {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_ROTATING
		} else {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_STATIC
		}

		refreshToken, err = h.tokenEngineIns.CreateRefreshToken(userData.Id)

		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		refreshExpiresAt, err := h.tokenEngineIns.GetRefreshTokenExpiry(refreshToken)
		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		_, err = h.services.User.StoreRefreshToken(ctx, userData.Id, refreshToken, refreshExpiresAt)
		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

	}

	resData := struct {
		AccessToken      string `json:"access_token"`
		RefreshTokenType string `json:"refresh_token_type,omitempty"`
		RefreshToken     string `json:"refresh_token,omitempty"`
	}{
		AccessToken:      accessToken,
		RefreshTokenType: refreshTokenType,
		RefreshToken:     refreshToken,
	}

	res.SetData(resData)
	res.Send(w)
}
