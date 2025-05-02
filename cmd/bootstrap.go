package main

import (
	"github.com/RyseUp/uniqora-nft-marketplace/auth"
	"github.com/RyseUp/uniqora-nft-marketplace/config"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/models"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/mq"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"log"
)

func initLogger() *zap.Logger {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer logger.Sync()

	return logger
}

func initDatabase(cfg *config.Config) *gorm.DB {
	db, err := config.ConnectDatabase(cfg,
		&models.User{},
		&models.UserRegister{},
		&models.UserSession{},
		&models.WalletNonce{},
	)

	if err != nil {
		log.Fatalf("db: %v", err)
	}

	return db
}

func initGoogleOAuth(cfg *config.Config, logger *zap.Logger) *oauth2.Config {
	googleConfig, err := auth.NewGoogleOAuthConfig(&cfg.Google)
	if err != nil {
		logger.Fatal("failed to initialize Google OAuth2 config", zap.Error(err))
	}

	return googleConfig
}

func initRabbitMQ(cfg *config.Config, logger *zap.Logger) *mq.EmailPublisher {
	publisher, err := mq.NewPublisher(cfg.RabbitMQ.URL, cfg.RabbitMQ.EmailQueue)
	if err != nil {
		logger.Fatal("failed to declare new publisher", zap.Error(err))
	}
	emailPublisher := mq.NewEmailPublisher(publisher, cfg.RabbitMQ.EmailQueue)

	return emailPublisher
}
