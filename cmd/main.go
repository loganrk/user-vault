package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"

	"github.com/loganrk/user-vault/internal/config"
	"github.com/loganrk/user-vault/internal/core/port"
	"github.com/loganrk/user-vault/internal/utils"

	handler "github.com/loganrk/user-vault/internal/adapter/handler/http"
	middleware "github.com/loganrk/user-vault/internal/adapter/middleware"
	oAuthProvider "github.com/loganrk/user-vault/internal/adapter/oAuth"
	repo "github.com/loganrk/user-vault/internal/adapter/repository/mysql"
	router "github.com/loganrk/user-vault/internal/adapter/router/gin"
	userSrv "github.com/loganrk/user-vault/internal/core/service/user"

	cipher "github.com/loganrk/utils-go/adapters/cipher/aes"
	logger "github.com/loganrk/utils-go/adapters/logger/zapLogger"
	message "github.com/loganrk/utils-go/adapters/message/kafka/producer"
	token "github.com/loganrk/utils-go/adapters/token/jwt"
)

func main() {
	envFile := os.Getenv("DEPLOYMENT_ENV_PATH")
	if envFile != "" {
		// If a custom environment file path is provided, load variables from that file
		err := godotenv.Load(envFile)
		if err != nil {
			log.Fatalf("Error loading %s file", envFile)
		}
	} else {
		log.Println("DEPLOYMENT_ENV_PATH is empty")
		return
	}

	// Fetch config file path from environment variables
	configFilePath := os.Getenv("CONFIG_FILE_PATH")

	// Extract the file name (e.g., "config.yaml")
	configFileName := filepath.Base(configFilePath)

	// Extract file base name and extension
	configBaseName := strings.TrimSuffix(configFileName, filepath.Ext(configFileName))
	configFileExt := strings.TrimPrefix(filepath.Ext(configFileName), ".")

	// Extract directory path containing the config file
	configDirPath := filepath.Dir(configFilePath)

	// Initialize application configuration using extracted components
	appConfig, err := config.StartConfig(configDirPath, config.File{
		Name: configBaseName,
		Ext:  configFileExt,
	})

	if err != nil {
		log.Println("failed to load config:", err)
		return
	}

	utilsIns := utils.New()

	// Initialize logger with the configuration settings
	loggerIns, err := initLogger(appConfig.GetLogger())
	if err != nil {
		log.Println("failed to initialize logger:", err)
		return
	}

	// Initialize database connection and auto-migrate the schema
	dbIns, err := initDatabase(appConfig)
	if err != nil {
		log.Println("failed to connect to database:", err)
		return
	}

	dbIns.AutoMigrate() // Auto-migrate schema

	// Initialize JWT token manager (HMAC/RSA) for handling authentication
	tokenIns, err := initTokenManager()
	if err != nil {
		log.Println("failed to setup token manager:", err)
		return
	}

	//Initialize Kafka message producer for event-driven messaging
	kafkaIns, err := initMessager(appConfig.GetAppName(), appConfig.GetKafka())
	if err != nil {
		log.Println("failed to setup kafka:", err)
		return
	}

	kafkaIns.RegisterVerification(appConfig.GetKafka().GetVerificationTopic())
	kafkaIns.RegisterPasswordReset(appConfig.GetKafka().GetPasswordResetTopic())

	oAuthProviderIns := initOauthProvider(appConfig.GetUser())

	// Initialize user service with necessary dependencies
	userService := userSrv.New(loggerIns, tokenIns, kafkaIns, dbIns, oAuthProviderIns, utilsIns, appConfig.GetAppName(), appConfig.GetUser())
	services := port.SvrList{User: userService}

	// Initialize middleware for API authentication and authorization
	middlewareIns := middleware.New(appConfig.GetMiddlewareApiKeys(), tokenIns)

	// Initialize HTTP handler to route requests to the appropriate services
	handlerIns := handler.New(loggerIns, tokenIns, services)

	// Set up and start the router with routes and handlers
	router := router.New(loggerIns)
	router.SetupRoutes(appConfig.GetApi(), loggerIns, middlewareIns, handlerIns)

	port := appConfig.GetAppPort()
	loggerIns.Infow(context.Background(), "Starting server", "port", port)
	loggerIns.Sync(context.Background())

	// Start the HTTP server and handle any errors during server startup
	if err := router.StartServer(port); err != nil {
		loggerIns.Errorw(context.Background(), "Server stopped with error", "port", port, "error", err)
		loggerIns.Sync(context.Background())
		return
	}

	// Log server shutdown if it stops without errors
	loggerIns.Infow(context.Background(), "Server stopped", "port", port)
	loggerIns.Sync(context.Background())
}

// initLogger creates and configures a zap-based logger using the provided configuration.
func initLogger(conf config.Logger) (port.Logger, error) {
	loggerConf := logger.Config{
		Level:          conf.GetLoggerLevel(),
		Encoding:       conf.GetLoggerEncodingMethod(),
		EncodingCaller: conf.GetLoggerEncodingCaller(),
		OutputPath:     conf.GetLoggerPath(),
	}
	return logger.New(loggerConf)
}

// initMessager sets up the Kafka message producer with the provided configuration.
func initMessager(appName string, conf config.Kafka) (port.Messager, error) {
	var brokers []string

	chiperEncryptEnabled := os.Getenv("CIPHER_SECRET_ENCRYPTION_ENABLED")
	if chiperEncryptEnabled == "true" {
		// Decrypt Kafka broker addresses using the provided cipher key
		cipherKey := os.Getenv("CIPHER_SECRET_KEY")
		cipher := cipher.New(cipherKey)

		// Decrypt each broker address and append to brokers slice
		for _, brokerEnc := range conf.GetBrokers() {
			broker, err := cipher.Decrypt(brokerEnc)
			if err != nil {
				return nil, err
			}
			brokers = append(brokers, broker)
		}
	} else {
		brokers = conf.GetBrokers()
	}
	// Pass the individual Kafka configuration parameters to the message.New function
	return message.New(appName,
		brokers,
		conf.GetClientID(),
		conf.GetVersion(),
		conf.GetRetryMax(),
	)

}

// initDatabase connects to the MySQL database using decrypted credentials from the config.
func initDatabase(conf config.App) (port.RepositoryMySQL, error) {

	// Decrypt each database configuration property
	host, port, user, pass, dbName, prefix := conf.GetStoreDatabaseProperties()

	chiperEncryptEnabled := os.Getenv("CIPHER_SECRET_ENCRYPTION_ENABLED")
	if chiperEncryptEnabled == "true" {
		// Decrypt database credentials using the provided cipher key
		cipherKey := os.Getenv("CIPHER_SECRET_KEY")
		cipher := cipher.New(cipherKey)

		var err error

		host, err = cipher.Decrypt(host)
		if err != nil {
			return nil, err
		}

		port, err = cipher.Decrypt(port)
		if err != nil {
			return nil, err
		}

		user, err = cipher.Decrypt(user)
		if err != nil {
			return nil, err
		}

		pass, err = cipher.Decrypt(pass)
		if err != nil {
			return nil, err
		}
	}

	// Pass the decrypted database configuration parameters to the repository.New function
	return repo.New(host, port, user, pass, dbName, prefix)
}

// initTokenManager sets up the JWT token manager using the provided JWT method and keys (RSA or HMAC).
func initTokenManager() (port.Token, error) {
	// Retrieve the JWT method and key file paths from environment variables
	method := os.Getenv("JWT_METHOD")
	privateKeyPath := os.Getenv("JWT_RSA_PRIVATE_KEY_PATH")
	publicKeyPath := os.Getenv("JWT_RSA_PUBLIC_KEY_PATH")
	hmacKey := os.Getenv("JWT_HMAC_KEY")

	// Pass the token configuration parameters to the token.New function
	return token.New(method, []byte(hmacKey), privateKeyPath, publicKeyPath)
}

// initOauthProvider initializes the OAuth provider adapter with configured client IDs.
func initOauthProvider(conf config.User) port.OAuthProvider {
	// Retrieve OAuth client IDs from configuration
	appleClientId := conf.GetAppleClientId()
	googleClientId := conf.GetGoogleClientId()
	microsoftClientId := conf.GetMicrosoftClientId()

	// Create and return the OAuth provider adapter
	return oAuthProvider.New(appleClientId, googleClientId, microsoftClientId)
}
