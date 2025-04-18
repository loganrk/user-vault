package v1

import (
	"context"
	"encoding/json"

	"userVault/internal/domain"
	"userVault/internal/utils"

	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/schema"
)

var (
	decoder  = schema.NewDecoder()
	validate = validator.New()
)

func init() {
	validate.RegisterValidation("password", func(fl validator.FieldLevel) bool {
		p := fl.Field().String()
		return len(p) >= 8 && utils.HasDigit(p) && utils.HasUppercase(p) && utils.HasLowercase(p) && utils.HasSpecialChar(p)
	})
}

func (h *handler) bindAndValidate(w http.ResponseWriter, r *http.Request, dst any) bool {
	var res response

	switch r.Method {
	case http.MethodPost:
		if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
			res.SetStatus(http.StatusBadRequest)
			res.SetError("invalid JSON payload")
			res.Send(w)
			return false
		}
	case http.MethodGet:
		if err := decoder.Decode(dst, r.URL.Query()); err != nil {
			res.SetStatus(http.StatusBadRequest)
			res.SetError("invalid query parameters")
			res.Send(w)
			return false
		}
	default:
		res.SetStatus(http.StatusMethodNotAllowed)
		res.SetError("unsupported request method")
		res.Send(w)
		return false
	}

	if err := validate.Struct(dst); err != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("validation failed: " + err.Error())
		res.Send(w)
		return false
	}

	return true
}

func (h *handler) UserLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var res response

	var req domain.UserLoginClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.Login(ctx, req)
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
	var res response

	var req domain.UserRegisterClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.Register(ctx, req)
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
	var res response

	var req domain.UserForgotPasswordClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.ForgotPassword(ctx, req)
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
	var res response

	var req domain.UserActivationClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.ActivateUser(ctx, req)
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
	var res response

	var req domain.UserLogoutClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.Logout(ctx, req)
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
	var res response

	var req domain.UserResetPasswordClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.ResetPassword(ctx, req)
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
	var res response

	var req domain.UserRefreshTokenValidateClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.ValidateRefreshToken(ctx, req)
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
	var res response

	var req domain.UserResendActivationClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.ResendActivation(ctx, req)
	if resErr != nil {
		res.SetStatus(resErr.StatusCode())
		res.SetError(resErr.MessageText())
		res.Send(w)
		return
	}

	res.SetData(respData)
	res.Send(w)
}
