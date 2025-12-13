package gin

import (
	"net/http"
	"time"

	"github.com/loganrk/user-vault/internal/core/port"
	"github.com/loganrk/user-vault/internal/infrastructure/config"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type route struct {
	gin       *gin.Engine
	accessLog port.Logger
}

// New creates a new instance of the Gin router with a custom access logger.
func New(accessLoggerIns port.Logger) *route {
	gin.DisableConsoleColor()

	r := gin.Default()

	// Add CORS middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},                             // Allow specific origin
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},  // Allowed methods
		AllowHeaders:     []string{"Authorization", "Content-Type"}, // Allowed headers
		ExposeHeaders:    []string{"Content-Length"},                // Headers exposed to the browser
		AllowCredentials: true,                                      // Allow credentials (cookies, Authorization header)
		MaxAge:           12 * time.Hour,                            // Preflight cache duration
	}))
	return &route{
		gin:       r,
		accessLog: accessLoggerIns,
	}
}

func (r *route) SetupRoutes(apiConfig config.Api, logger port.Logger, middlewareIns port.GinMiddleware, handler port.Handler) {

	apiKeyProtectedRoutes := r.gin.Group("/")
	apiKeyProtectedRoutes.Use(wrapHTTPMiddleware(middlewareIns.ValidateApiKey()))
	if apiConfig.GetUserLoginEnabled() {
		method, route := apiConfig.GetUserLoginProperties()
		wrapAndRegisterRoute(apiKeyProtectedRoutes, method, route, handler.UserLogin)
	}

	// User Logout
	if apiConfig.GetUserOauthLoginEnabled() {
		method, route := apiConfig.GetUserOauthLoginProperties()
		wrapAndRegisterRoute(apiKeyProtectedRoutes, method, route, handler.UserOAuthLogin)
	}

	// User Register
	if apiConfig.GetUserRegisterEnabled() {
		method, route := apiConfig.GetUserRegisterProperties()
		wrapAndRegisterRoute(apiKeyProtectedRoutes, method, route, handler.UserRegister)
	}

	// User Verify
	if apiConfig.GetUserVerifyEnabled() {
		method, route := apiConfig.GetUserVerifyProperties()
		wrapAndRegisterRoute(apiKeyProtectedRoutes, method, route, handler.UserVerify)
	}

	// User Resend Verification
	if apiConfig.GetUserResendVerificationEnabled() {
		method, route := apiConfig.GetUserResendVerificationProperties()
		wrapAndRegisterRoute(apiKeyProtectedRoutes, method, route, handler.UserResendVerification)
	}

	// User Forgot Password
	if apiConfig.GetUserForgotPasswordEnabled() {
		method, route := apiConfig.GetUserForgotPasswordProperties()
		wrapAndRegisterRoute(apiKeyProtectedRoutes, method, route, handler.UserForgotPassword)
	}

	// User Password Reset
	if apiConfig.GetUserPasswordResetEnabled() {
		method, route := apiConfig.GetUserPasswordResetProperties()
		wrapAndRegisterRoute(apiKeyProtectedRoutes, method, route, handler.UserPasswordReset)
	}

	refreshTokenProtectedRoutes := r.gin.Group("/")
	refreshTokenProtectedRoutes.Use(wrapHTTPMiddleware(middlewareIns.ValidateRefreshToken()))

	// User Refresh Token Validate
	if apiConfig.GetUserRefreshTokenEnabled() {
		method, route := apiConfig.GetUserRefreshTokenProperties()
		wrapAndRegisterRoute(refreshTokenProtectedRoutes, method, route, handler.UserRefreshToken)
	}

	// User Logout
	if apiConfig.GetUserLogoutEnabled() {
		method, route := apiConfig.GetUserLogoutProperties()
		wrapAndRegisterRoute(refreshTokenProtectedRoutes, method, route, handler.UserLogout)
	}

}

// StartServer starts the Gin HTTP server on the specified port.
func (r *route) StartServer(port string) error {
	// Run the Gin server on the specified port
	return r.gin.Run(":" + port)
}

func wrapAndRegisterRoute(group *gin.RouterGroup, method, path string, handlerFunc http.HandlerFunc) {
	switch method {
	case "GET":
		group.GET(path, func(c *gin.Context) {
			handlerFunc.ServeHTTP(c.Writer, c.Request)
		})
	case "POST":
		group.POST(path, func(c *gin.Context) {
			handlerFunc.ServeHTTP(c.Writer, c.Request)
		})
	case "PUT":
		group.PUT(path, func(c *gin.Context) {
			handlerFunc.ServeHTTP(c.Writer, c.Request)
		})
	case "DELETE":
		group.DELETE(path, func(c *gin.Context) {
			handlerFunc.ServeHTTP(c.Writer, c.Request)
		})
	default:
		panic("Unsupported HTTP method: " + method)
	}
}

func wrapHTTPMiddleware(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a new http request/response pair
		h.ServeHTTP(c.Writer, c.Request)
		if c.Writer.Status() >= 400 {
			c.Abort()
		}
	}
}
