package v1

import (
	"context"
	request "mayilon/internal/adapters/handler/http/v1/request/user"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/core/constant.go"
	"net/http"
	"time"
)

func (h *handler) UserRefreshTokenValidate(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserRefreshTokenValidate()
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
		res.SetError(ERROR_CODE_TOKEN_EXPIRED, "token expired")
		res.Send(w)
		return
	}

	refreshTokenData, err := h.services.User.GetRefreshTokenData(ctx, userid, req.RefreshToken)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if refreshTokenData.Id == 0 {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_INCORRECT, "incorrect token")
		res.Send(w)
		return
	}

	if refreshTokenData.Revoked {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_REVOKED, "token revoked")
		res.Send(w)
		return
	}

	if refreshTokenData.ExpiresAt.Before(time.Now()) {
		res.SetStatus(http.StatusBadRequest)
		res.SetError(ERROR_CODE_TOKEN_EXPIRED, "token expired")
		res.Send(w)
		return
	}

	userData, err := h.services.User.GetUserByUserid(ctx, userid)
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

	if h.services.User.RefreshTokenEnabled() {
		accessToken, err = h.tokenEngineIns.CreateAccessToken(userData.Id, userData.Username, userData.Name)
		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
			res.Send(w)
			return
		}

		if h.services.User.RefreshTokenRotationEnabled() {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_ROTATING

			err = h.services.User.RevokedRefreshToken(ctx, userid, req.RefreshToken)
			if err != nil {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
				res.Send(w)
				return
			}

			refreshToken, err := h.tokenEngineIns.CreateRefreshTokenWithCustomExpiry(userid, refreshTokenData.ExpiresAt)
			if err != nil {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
				res.Send(w)
				return
			}

			tokenId, err := h.services.User.StoreRefreshToken(ctx, userid, refreshToken, refreshTokenData.ExpiresAt)
			if err != nil {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
				res.Send(w)
				return
			}

			if tokenId == 0 {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
				res.Send(w)
				return
			}

		} else {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_STATIC
			refreshToken = req.RefreshToken
		}

	} else {
		res.SetStatus(http.StatusForbidden)
		res.SetError(ERROR_CODE_TOKEN_NOT_AVAILABLE, "token is not available")
		res.Send(w)
		return
	}

	resData := struct {
		AccessToken      string `json:"access_token"`
		RefreshTokenType string `json:"refresh_token_type,omitempty"`
		RefreshToken     string `json:"refresh_token"`
	}{
		AccessToken:      accessToken,
		RefreshTokenType: refreshTokenType,
		RefreshToken:     refreshToken,
	}

	res.SetData(resData)
	res.Send(w)

}
