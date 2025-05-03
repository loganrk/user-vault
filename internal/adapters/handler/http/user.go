package http

import (
	"context"
	"encoding/json"

	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/utils"

	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/schema"
)

// Global variables for decoder and validator
// decoder is used to decode query parameters from the URL
// validate is used for validating struct fields (e.g., custom validation rules like password strength)
var (
	decoder  = schema.NewDecoder() // Schema decoder for query parameter binding
	validate = validator.New()     // Validator instance for struct validation
)

// init function registers custom validation rules for fields such as "password".
// This ensures passwords meet certain criteria: minimum length, containing digits, uppercase, lowercase, and special characters.
func init() {
	validate.RegisterValidation("password", func(fl validator.FieldLevel) bool {
		p := fl.Field().String()
		return len(p) >= 8 && utils.HasDigit(p) && utils.HasUppercase(p) && utils.HasLowercase(p) && utils.HasSpecialChar(p)
	})
}

// bindAndValidate handles the decoding of request data (either JSON for POST or query parameters for GET)
// and performs validation of the decoded data. If any errors occur, it sends an appropriate error response.
func (h *handler) bindAndValidate(w http.ResponseWriter, r *http.Request, dst any) bool {
	var res response

	switch r.Method {
	case http.MethodPost:
		// Decode the POST body JSON into the provided destination struct
		if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
			res.SetStatus(http.StatusBadRequest)
			res.SetError("invalid JSON payload") // Error if the body cannot be parsed
			res.Send(w)
			return false
		}
	case http.MethodGet:
		// Decode the GET query parameters into the destination struct
		if err := decoder.Decode(dst, r.URL.Query()); err != nil {
			res.SetStatus(http.StatusBadRequest)
			res.SetError("invalid query parameters") // Error if query parameters are invalid
			res.Send(w)
			return false
		}
	default:
		// Return error for unsupported request methods
		res.SetStatus(http.StatusMethodNotAllowed)
		res.SetError("unsupported request method")
		res.Send(w)
		return false
	}

	// Perform validation on the decoded data (e.g., ensuring that the fields meet the specified criteria)
	if err := validate.Struct(dst); err != nil {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("validation failed: " + err.Error()) // Validation error message
		res.Send(w)
		return false
	}

	return true
}

// UserLogin handles user login requests by decoding the login request, validating the data, and then
// invoking the usecase for login. If successful, it returns the response data, otherwise returns an error.
func (h *handler) UserLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var res response

	var req domain.UserLoginClientRequest
	// Bind and validate the incoming request
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	// Call the login usecase
	respData, resErr := h.usecases.User.Login(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful login response
	res.SetStatus(http.StatusOK)
	res.SetData(respData)
	res.Send(w)
}

// UserRegister handles user registration requests. It decodes the registration data, validates it,
// and then invokes the usecase for user registration. If successful, it returns the response data, otherwise an error.
func (h *handler) UserRegister(w http.ResponseWriter, r *http.Request) {

	ctx := context.Background()
	var res response
	var req domain.UserRegisterClientRequest
	// Bind and validate the incoming request
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	if req.Email == "" && req.Phone == "" {
		res.SetStatus(http.StatusBadRequest)
		res.SetError("validation failed: email address or phone number is required ") // Validation error message
		res.Send(w)
		return
	}

	// Call the registration usecase
	respData, resErr := h.usecases.User.Register(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful registration response
	res.SetData(respData)
	res.Send(w)
}

// UserForgotPassword handles forgot password requests. It decodes the request, validates it,
// and then invokes the usecase for resetting the password. Returns an appropriate response based on success or failure.
func (h *handler) UserForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var res response

	var req domain.UserForgotPasswordClientRequest
	// Bind and validate the incoming request
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	// Call the forgot password usecase
	respData, resErr := h.usecases.User.ForgotPassword(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful response with reset data
	res.SetData(respData)
	res.Send(w)
}

// UserActivation handles user account activation requests. It validates the activation token and
// invokes the usecase to activate the user account. Returns the response based on the outcome.
func (h *handler) UserActivation(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var res response

	var req domain.UserActivationClientRequest
	// Bind and validate the incoming request
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	// Call the user activation usecase
	respData, resErr := h.usecases.User.ActivateUser(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful account activation response
	res.SetData(respData)
	res.Send(w)
}

// UserLogout handles user logout requests. It decodes the logout request, validates the data,
// and invokes the logout usecase. Returns the appropriate response based on success or failure.
func (h *handler) UserLogout(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var res response

	refreshToken := r.Header.Get("Authorization")
	var req = domain.UserLogoutClientRequest{
		RefreshToken: utils.ExtractBearerToken(refreshToken),
	}

	respData, resErr := h.usecases.User.Logout(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful logout response
	res.SetData(respData)
	res.Send(w)
}

// UserPasswordReset handles password reset requests. It validates the password reset data and invokes
// the reset password usecase. Returns the result of the operation.
func (h *handler) UserPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var res response

	var req domain.UserResetPasswordClientRequest
	// Bind and validate the incoming request
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	// Call the reset password usecase
	respData, resErr := h.usecases.User.ResetPassword(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful password reset response
	res.SetData(respData)
	res.Send(w)
}

// UserRefreshToken handles requests to validate refresh tokens. It decodes the request, validates it,
// and invokes the token validation usecase. Returns the response based on success or failure.
func (h *handler) UserRefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var res response

	refreshToken := r.Header.Get("Authorization")

	var req = domain.UserRefreshTokenClientRequest{
		RefreshToken: utils.ExtractBearerToken(refreshToken),
	}

	// Call the refresh token validation usecase
	respData, resErr := h.usecases.User.RefreshToken(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful refresh token validation response
	res.SetData(respData)
	res.Send(w)
}

// UserResendActivation handles requests to resend an activation email. It decodes the request,
// validates it, and invokes the resend activation usecase. Returns the response based on the outcome.
func (h *handler) UserResendActivation(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var res response

	var req domain.UserResendActivationClientRequest
	// Bind and validate the incoming request
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	// Call the resend activation usecase
	respData, resErr := h.usecases.User.ResendActivation(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message) // Set the error message if registration fails
		res.Send(w)
		return
	}

	// Successful resend activation response
	res.SetData(respData)
	res.Send(w)
}

func (h *handler) UserOAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var res response

	var req domain.UserOAuthLoginClientRequest
	if !h.bindAndValidate(w, r, &req) {
		return
	}

	respData, resErr := h.usecases.User.OAuthLogin(ctx, req)
	if resErr.Code != 0 {
		res.SetStatus(resErr.Code)
		res.SetError(resErr.Message)
		res.Send(w)
		return
	}

	res.SetStatus(http.StatusOK)
	res.SetData(respData)
	res.Send(w)
}
