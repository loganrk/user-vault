package handler

import (
	"context"
	request "mayilon/pkg/http/v1/request/user"
	"mayilon/pkg/http/v1/response"
	"mayilon/pkg/types"
	"net/http"
	"time"
)

func (h *Handler) UserRefreshTokenValidate(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserRefreshTokenValidate()
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

	userid, expiresAt, err := h.authentication.GetRefreshTokenData(req.RefreshToken)

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

	refreshTokenData := h.services.User.GetRefreshTokenData(ctx, userid, req.RefreshToken)
	if refreshTokenData.Id == 0 {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if refreshTokenData.Revoked {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("token is revoked")
		res.Send(w)
		return
	}

	if refreshTokenData.ExpiresAt.Before(time.Now()) {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("token is expired")
		res.Send(w)
		return
	}
	var accessToken, refreshTokenType, refreshToken string

	if h.services.User.RefreshTokenEnabled() {
		accessToken, err = h.authentication.CreateAccessToken(userid)
		if err != nil {
			res.SetStatus(http.StatusInternalServerError)
			res.SetError("internal server error")
			res.Send(w)
			return
		}

		if h.services.User.RefreshTokenRotationEnabled() {
			refreshTokenType = types.REFRESH_TOKEN_TYPE_ROTATING

			result2 := h.services.User.RevokedRefreshToken(ctx, userid, req.RefreshToken)
			if !result2 {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError("internal server error")
				res.Send(w)
				return
			}

			refreshToken, err := h.authentication.CreateRefreshTokenWithCustomExpiry(userid, refreshTokenData.ExpiresAt)
			if err != nil {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError("internal server error")
				res.Send(w)
				return
			}

			tokenId := h.services.User.StoreRefreshToken(ctx, userid, refreshToken, refreshTokenData.ExpiresAt)
			if tokenId == 0 {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError("internal server error")
				res.Send(w)
				return
			}

		} else {
			refreshTokenType = types.REFRESH_TOKEN_TYPE_STATIC
			refreshToken = req.RefreshToken

		}

	} else {
		res.SetStatus(http.StatusForbidden)
		res.SetError("token not able to generate")
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
