package main

import (
	"context"
	"log"
	"os"

	"github.com/joho/godotenv"

	"github.com/loganrk/user-vault/config"
	"github.com/loganrk/user-vault/internal/core/port"

	handler "github.com/loganrk/user-vault/internal/adapters/handler/http"
	ginmiddleware "github.com/loganrk/user-vault/internal/adapters/middleware/gin"
	repo "github.com/loganrk/user-vault/internal/adapters/repository/mysql"
	userUsecase "github.com/loganrk/user-vault/internal/core/usecase/user"
	router "github.com/loganrk/user-vault/internal/router/gin"

	cipher "github.com/loganrk/utils-go/adapters/cipher/aes"
	logger "github.com/loganrk/utils-go/adapters/logger/zapLogger"
	message "github.com/loganrk/utils-go/adapters/message/kafka/producer"
	token "github.com/loganrk/utils-go/adapters/token/jwt"
)

func main() {
	// Load environment variables from .env file for application configuration
	godotenv.Load()

	// Fetch config file path, name, and type from environment variables
	configPath := os.Getenv("CONFIG_FILE_PATH")
	configName := os.Getenv("CONFIG_FILE_NAME")
	configType := os.Getenv("CONFIG_FILE_TYPE")

	// Initialize application configuration using the provided details
	appConfig, err := config.StartConfig(configPath, config.File{
		Name: configName,
		Ext:  configType,
	})
	if err != nil {
		log.Println("failed to load config:", err)
		return
	}

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

	kafkaIns.RegisterVerification(appConfig.GetKafka().GetPasswordResetTopic())
	kafkaIns.RegisterPasswordReset(appConfig.GetKafka().GetPasswordResetTopic())

	// Initialize user service with necessary dependencies
	userService := userUsecase.New(loggerIns, tokenIns, kafkaIns, dbIns, appConfig.GetAppName(), appConfig.GetUser())
	services := port.SvrList{User: userService}

	// Initialize ginmiddlewareIns for API authentication and authorization
	ginmiddlewareIns := ginmiddleware.New(appConfig.GetMiddlewareApiKeys(), tokenIns)

	// Initialize HTTP handler to route requests to the appropriate services
	handlerIns := handler.New(loggerIns, tokenIns, services)

	// Set up and start the router with routes and handlers
	router := router.New(loggerIns)
	router.SetupRoutes(appConfig.GetApi(), loggerIns, ginmiddlewareIns, handlerIns)

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
	// Decrypt Kafka broker addresses using the provided cipher key
	cipherKey := os.Getenv("CIPHER_CRYPTO_KEY")
	cipher := cipher.New(cipherKey)
	var brokers []string

	// Decrypt each broker address and append to brokers slice
	for _, brokerEnc := range conf.GetBrokers() {
		broker, err := cipher.Decrypt(brokerEnc)
		if err != nil {
			return nil, err
		}
		brokers = append(brokers, broker)
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
	// Decrypt database credentials using the provided cipher key
	cipherKey := os.Getenv("CIPHER_CRYPTO_KEY")
	cipher := cipher.New(cipherKey)

	// Decrypt each database configuration property
	hostEnc, portEnc, userEnc, passEnc, dbName, prefix := conf.GetStoreDatabaseProperties()

	host, err := cipher.Decrypt(hostEnc)
	if err != nil {
		return nil, err
	}
	portVal, err := cipher.Decrypt(portEnc)
	if err != nil {
		return nil, err
	}
	user, err := cipher.Decrypt(userEnc)
	if err != nil {
		return nil, err
	}
	pass, err := cipher.Decrypt(passEnc)
	if err != nil {
		return nil, err
	}

	// Pass the decrypted database configuration parameters to the repository.New function
	return repo.New(host, portVal, user, pass, dbName, prefix)
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
