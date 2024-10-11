package v1

import (
	"context"
	"mayilon/internal/adapters/handler/http/v1/request"
	"mayilon/internal/adapters/handler/http/v1/response"
	"mayilon/internal/constant"
	"mayilon/internal/port"
	"net/http"
)

func (h *handler) UserForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserForgotPassword(r)
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

	userData, err := h.usecases.User.GetUserByUsername(ctx, req.GetUsername())
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

	tokenId, passwordResetToken, err := h.usecases.User.CreatePasswordResetToken(ctx, userData.Id)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
		res.Send(w)
		return
	}

	if tokenId != 0 && passwordResetToken != "" {
		passwordResetLink := h.usecases.User.GetPasswordResetLink(passwordResetToken)
		if passwordResetLink != "" {
			template, err := h.usecases.User.GetPasswordResetEmailTemplate(ctx, userData.Name, passwordResetLink)
			if err != nil {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
				res.Send(w)
				return
			}

			if template != "" {
				err := h.usecases.User.SendPasswordReset(ctx, userData.Username, template)
				if err != nil {
					res.SetStatus(http.StatusInternalServerError)
					res.SetError(ERROR_CODE_INTERNAL_SERVER, "internal server error")
					res.Send(w)
					return
				}
				resData := port.UserForgotPasswordClientResponse{
					Message: "account created successfuly. please check your email for activate account",
				}
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
