package gin

import (
	"context"
	"net/http"
	"time"

	"github.com/loganrk/user-vault/internal/core/port"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type route struct {
	gin       *gin.Engine
	server    *http.Server
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

func (r *route) SetupRoutes(
	logger port.Logger,
	middlewareIns port.Middleware,
	handler port.Handler,
) {

	// ===============================
	// API Key Protected Routes
	// ===============================
	api := r.gin.Group("/api/v1")
	api.Use(wrapHTTPMiddleware(middlewareIns.ValidateApiKey()))

	// User Login
	wrapAndRegisterRoute(api, "POST", "login", handler.UserLogin)

	// User OAuth Login
	wrapAndRegisterRoute(api, "POST", "oAuthlogin", handler.UserOAuthLogin)

	// User Register
	wrapAndRegisterRoute(api, "POST", "register", handler.UserRegister)

	// User Verify
	wrapAndRegisterRoute(api, "POST", "verify", handler.UserVerify)

	// User Resend Verification
	wrapAndRegisterRoute(api, "POST", "resend-verification", handler.UserResendVerification)

	// User Forgot Password
	wrapAndRegisterRoute(api, "POST", "forgot-password", handler.UserForgotPassword)

	// User Password Reset
	wrapAndRegisterRoute(api, "POST", "reset-password", handler.UserPasswordReset)

	// ===============================
	// Refresh Token Protected Routes
	// ===============================
	refresh := r.gin.Group("/api/v1")
	refresh.Use(wrapHTTPMiddleware(middlewareIns.ValidateRefreshToken()))

	// Refresh Token
	wrapAndRegisterRoute(refresh, "POST", "refresh-token", handler.UserRefreshToken)

	// Logout
	wrapAndRegisterRoute(refresh, "POST", "logout", handler.UserLogout)
}

// StartServer starts the Gin HTTP server on the specified port.
func (r *route) StartServer(port string) error {
	r.server = &http.Server{
		Addr:    ":" + port,
		Handler: r.gin,
	}

	return r.server.ListenAndServe()
}

// StartServer starts the Gin HTTP server on the specified port.
func (r *route) Shutdown(ctx context.Context) error {
	return r.server.Shutdown(ctx)
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
