package handler

import (
	"context"
	"mayilon/pkg/http/v1/request"
	"mayilon/pkg/http/v1/response"
	"mayilon/pkg/types"
	"net/http"
)

func (h *Handler) UserForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserForgotPassword()
	res := response.New()

	err := req.Parse(r)
	if err != nil {
		// TODO log
		res.SetError("invalid request parameters")
		res.Send(w)
		return
	}

	result := req.Validate()
	if result != "" {
		res.SetError(result)
		res.Send(w)
		return
	}

	userData := h.Services.User.GetUserByUsername(ctx, req.Username)
	if userData.Id == 0 {
		res.SetError("username is incorrect")
		res.Send(w)
		return
	}

	if userData.Status != types.USER_STATUS_ACTIVE {
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

	tokenId, passwordResetToken := h.Services.User.CreatePasswordResetToken(ctx, userData.Id)
	if tokenId != 0 && passwordResetToken != "" {
		passwordResetLink := h.Services.User.GetPasswordResetLink(passwordResetToken)
		if passwordResetLink != "" {
			template := h.Services.User.GetPasswordResetEmailTemplate(ctx, userData.Name, passwordResetLink)
			if template != "" {
				emailStatus := h.Services.User.SendPasswordReset(ctx, userData.Username, template)
				if emailStatus == types.EMAIL_STATUS_SUCCESS {
					resData := "account created successfuly. please check your email for activate account"
					res.SetData(resData)
					res.Send(w)
					return
				}
			}
		}

	}

	res.SetError("internal server error")
	res.Send(w)

}
