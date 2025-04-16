package main

import (
	"context"
	user "github.com/RyseUp/uniqora-nft-marketplace/backend/api/user/v1/v1connect"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/config"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/models"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/mq"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/repositories"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/security"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/services"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/worker"
	"github.com/bufbuild/connect-go"
	"log"
	"net/http"
)

func main() {
	cfg := config.Load()

	db, err := config.ConnectDatabase(cfg,
		&models.User{},
		&models.UserRegister{},
		&models.UserSession{},
	)

	if err != nil {
		log.Fatalf("db: %v", err)
	}

	// http-router-service
	mux := http.NewServeMux()

	// setting-interceptor
	interceptor := connect.WithInterceptors(
		security.AuthInterceptor(cfg.JWT.SecretKey),
		security.SetAccessTokenCookieInterceptor(),
	)

	// user-service-setting
	publisher, err := mq.NewPublisher(cfg.RabbitMQ.URL, cfg.RabbitMQ.EmailQueue)
	if err != nil {
		log.Fatalf("rabbitmq: %v", err)
	}
	emailPublisher := mq.NewEmailPublisher(publisher, cfg.RabbitMQ.EmailQueue)
	userRepo := repositories.NewUserStore(db)
	userService := services.NewUserAPI(cfg, userRepo, emailPublisher)

	// authentication-user-service
	userPath, userHandler := user.NewUserAccountAPIHandler(userService, interceptor)
	mux.Handle(userPath, userHandler)

	// email-consumer-worker
	go func() {
		consumer, err := worker.NewEmailConsumer(cfg)
		if err != nil {
			log.Fatalf("worker init: %v", err)
		}
		if err := consumer.Start(context.Background()); err != nil {
			log.Fatalf("worker run: %v", err)
		}
	}()

	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", mux)
}
