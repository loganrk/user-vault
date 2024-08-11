package handler

import (
	"context"
	request "mayilon/pkg/http/v1/request/user"
	"mayilon/pkg/http/v1/response"
	"mayilon/pkg/types"
	"net/http"
)

func (h *Handler) UserResendActivation(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	req := request.NewUserResendActivation()
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

	userData, err := h.services.User.GetUserByUsername(ctx, req.Username)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if userData.Id == 0 {
		res.SetStatus(http.StatusUnauthorized)
		res.SetError("username is incorrect")
		res.Send(w)
		return
	}

	if userData.Status != types.USER_STATUS_PENDING {

		res.SetStatus(http.StatusForbidden)

		if userData.Status == types.USER_STATUS_ACTIVE {
			res.SetError("your account is already activated")
		} else if userData.Status == types.USER_STATUS_INACTIVE {
			res.SetError("your account is currently inactive")
		} else {
			res.SetError("your account has been banned")
		}

		res.Send(w)
		return
	}

	tokenId, activationToken, err := h.services.User.CreateActivationToken(ctx, userData.Id)
	if err != nil {
		res.SetStatus(http.StatusInternalServerError)
		res.SetError("internal server error")
		res.Send(w)
		return
	}

	if tokenId != 0 && activationToken != "" {
		activationLink := h.services.User.GetActivationLink(tokenId, activationToken)
		if activationLink != "" {
			template, err := h.services.User.GetActivationEmailTemplate(ctx, userData.Name, activationLink)
			if err != nil {
				res.SetStatus(http.StatusInternalServerError)
				res.SetError("internal server error")
				res.Send(w)
				return
			}
			if template != "" {
				err = h.services.User.SendActivation(ctx, userData.Username, template)
				if err != nil {
					res.SetStatus(http.StatusInternalServerError)
					res.SetError("internal server error")
					res.Send(w)
					return
				}
				resData := "please check your email for activate account"
				res.SetData(resData)
				res.Send(w)
				return
			}
		}

	}

	res.SetStatus(http.StatusInternalServerError)
	res.SetError("internal server error")
	res.Send(w)
}
