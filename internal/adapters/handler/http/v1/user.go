package v1

import (
	"context"

	"mayilon/internal/adapters/handler/http/v1/request"
	"mayilon/internal/adapters/handler/http/v1/response"

	"net/http"
)

func (h *handler) UserLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context() // Use request context for tracing, timeouts, etc.
	res := response.New()

	req, err := request.NewUserLogin(r)
	if err != nil || req.Validate() != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("Invalid login request")
		res.Send(w)
		return
	}

	respData, resErr := h.usecases.User.Login(ctx, req.GetUsername(), req.GetPassword())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetStatus(http.StatusOK)
	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserRegister(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserRegister(r)
	if err != nil || req.Validate() != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid request parameters")
		res.Send(w)
		return
	}

	respData, resErr := h.usecases.User.Register(ctx, req.GetUsername(), req.GetPassword(), req.GetName())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserForgotPassword(r)
	if err != nil || req.Validate() != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid request")
		res.Send(w)
		return
	}

	respData, resErr := h.usecases.User.ForgotPassword(ctx, req.GetUsername())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserActivation(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserActivation(r)
	if err != nil || req.Validate() != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid activation request")
		res.Send(w)
		return
	}

	respData, resErr := h.usecases.User.ActivateUser(ctx, req.GetToken())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserLogout(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserLogout(r)
	if err != nil || req.Validate() != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid request parameters")
		res.Send(w)
		return
	}

	respData, resErr := h.usecases.User.Logout(ctx, req.GetRefreshToken())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserResetPassword(r)
	if err != nil || req.Validate() != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("invalid request")
		res.Send(w)
		return
	}

	respData, resErr := h.usecases.User.ResetPassword(ctx, req.GetToken(), req.GetPassword())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserRefreshTokenValidate(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserRefreshTokenValidate(r)
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

	respData, resErr := h.usecases.User.ValidateRefreshToken(ctx, req.GetRefreshToken())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserResendActivation(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	res := response.New()

	req, err := request.NewUserResendActivation(r)
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

	respData, resErr := h.usecases.User.ResendActivation(ctx, req.GetUsername())
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}
