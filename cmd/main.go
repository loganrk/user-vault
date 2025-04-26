package main

import (
	"context"
	"log"
	"os"

	"github.com/joho/godotenv"

	"user-vault/config"
	"user-vault/internal/core/port"

	aesCipher "user-vault/internal/adapters/cipher/aes"
	httpHandler "user-vault/internal/adapters/handler/http/v1"
	zapLogger "user-vault/internal/adapters/logger/zapLogger"
	kafkaMessage "user-vault/internal/adapters/message/kafka"
	authMiddleware "user-vault/internal/adapters/middleware/auth"
	mysqlRepo "user-vault/internal/adapters/repository/mysql"
	ginRouter "user-vault/internal/adapters/router/gin"
	jwtToken "user-vault/internal/adapters/token/jwt"
	userUsecase "user-vault/internal/core/usecase/user"
)

func main() {
	// Load environment variables from .env file
	godotenv.Load()

	// Read config file path, name, and type from environment variables
	configPath := os.Getenv("CONFIG_FILE_PATH")
	configName := os.Getenv("CONFIG_FILE_NAME")
	configType := os.Getenv("CONFIG_FILE_TYPE")

	// Initialize application configuration
	appConfig, err := config.StartConfig(configPath, config.File{
		Name: configName,
		Ext:  configType,
	})
	if err != nil {
		log.Println("failed to load config:", err)
		return
	}

	// Initialize logger
	logger, err := initLogger(appConfig.GetLogger())
	if err != nil {
		log.Println("failed to initialize logger:", err)
		return
	}

	// Initialize database connection
	db, err := initDatabase(appConfig)
	if err != nil {
		log.Println("failed to connect to database:", err)
		return
	}
	db.AutoMigrate() // Auto-migrate schema

	// Initialize token service (JWT)
	tokenIns, err := initTokenManager()
	if err != nil {
		log.Println("failed to setup token manager:", err)
		return
	}

	kafkaIns, err := initKafka(appConfig.GetAppName(), appConfig.GetKafka())
	if err != nil {
		log.Println("failed to setup kafka:", err)
		return
	}

	// Initialize user service
	userService := userUsecase.New(logger, tokenIns, kafkaIns, db, appConfig.GetAppName(), appConfig.GetUser())
	services := port.SvrList{User: userService}

	authMiddlewareIns := authMiddleware.New(appConfig.GetMiddlewareApiKeys(), tokenIns)
	handlerIns := httpHandler.New(logger, tokenIns, services)

	router := ginRouter.New(logger)
	router.SetupRoutes(appConfig.GetApi(), logger, authMiddlewareIns, handlerIns)

	port := appConfig.GetAppPort()
	logger.Infow(context.Background(), "Starting server", "port", port)
	logger.Sync(context.Background())

	// Start HTTP server
	if err := router.StartServer(port); err != nil {
		logger.Errorw(context.Background(), "Server stopped with error", "port", port, "error", err)
		logger.Sync(context.Background())
		return
	}

	logger.Infow(context.Background(), "Server stopped", "port", port)
	logger.Sync(context.Background())
}

// initLogger creates a new zap-based logger with the given config.
func initLogger(conf config.Logger) (port.Logger, error) {
	loggerConf := zapLogger.Config{
		Level:          conf.GetLoggerLevel(),
		Encoding:       conf.GetLoggerEncodingMethod(),
		EncodingCaller: conf.GetLoggerEncodingCaller(),
		OutputPath:     conf.GetLoggerPath(),
	}
	return zapLogger.New(loggerConf)
}

func initKafka(appName string, conf config.Kafka) (port.Messager, error) {
	cipherKey := os.Getenv("CIPHER_CRYPTO_KEY")
	cipher := aesCipher.New(cipherKey)
	var brokers []string

	for _, brokerEnc := range conf.GetBrokers() {
		broker, err := cipher.Decrypt(brokerEnc)
		if err != nil {
			return nil, err
		}
		brokers = append(brokers, broker)
	}

	return kafkaMessage.New(appName, brokers, conf)
}

// initDatabase connects to the MySQL database using decrypted credentials.
func initDatabase(conf config.App) (port.RepositoryMySQL, error) {
	cipherKey := os.Getenv("CIPHER_CRYPTO_KEY")
	cipher := aesCipher.New(cipherKey)

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

	return mysqlRepo.New(host, portVal, user, pass, dbName, prefix)
}

// initTokenManager sets up JWT token manager with RSA or HMAC keys.
func initTokenManager() (port.Token, error) {

	method := os.Getenv("JWT_METHOD")
	privateKeyPath := os.Getenv("JWT_RSA_PRIVATE_KEY_PATH")
	publicKeyPath := os.Getenv("JWT_RSA_PUBLIC_KEY_PATH")
	hmacKey := os.Getenv("JWT_HMAC_KEY")

	return jwtToken.New(method, []byte(hmacKey), privateKeyPath, publicKeyPath)
}
