package v1

import (
	"context"
	request "mayilon/internal/adapters/handler/http/v1/request/user"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/core/constant"
	"net/http"
)

func (h *handler) UserForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserForgotPassword()
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
		res.SetError(ERROR_CODE_USERNAME_INCORRECT, "username is incorrect")
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

	tokenId, passwordResetToken, err := h.services.User.CreatePasswordResetToken(ctx, userData.Id)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if tokenId != 0 && passwordResetToken != "" {
		passwordResetLink := h.services.User.GetPasswordResetLink(passwordResetToken)
		if passwordResetLink != "" {
			template, err := h.services.User.GetPasswordResetEmailTemplate(ctx, userData.Name, passwordResetLink)
			if err != nil {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
				res.Send(w)
				return
			}

			if template != "" {
				err := h.services.User.SendPasswordReset(ctx, userData.Username, template)
				if err != nil {
					res.SetStatus(http.StatusInternalServerError)
					res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
					res.Send(w)
					return
				}
				resData := "account created successfuly. please check your email for activate account"
				res.SetData(resData)
				res.Send(w)
				return
			}
		}
	}

	res.SetStatus(http.StatusInternalServerError)
	res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
	res.Send(w)

}
