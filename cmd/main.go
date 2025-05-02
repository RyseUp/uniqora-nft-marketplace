package main

import (
	user "github.com/RyseUp/uniqora-nft-marketplace/api/user/v1/v1connect"
	"github.com/RyseUp/uniqora-nft-marketplace/config"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/repositories"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/security"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/services"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/worker"
	"github.com/bufbuild/connect-go"
	"go.uber.org/zap"
	"net/http"
)

func main() {
	cfg := config.Load()
	logger := initLogger()
	db := initDatabase(cfg)
	googleConfig := initGoogleOAuth(cfg, logger)
	emailPublisher := initRabbitMQ(cfg, logger)

	// init repo
	var (
		userRepo        = repositories.NewUserStore(db)
		walletNonceRepo = repositories.NewWalletNonce(db)
	)

	// setting-interceptor
	interceptor := connect.WithInterceptors(
		security.AuthInterceptor(cfg.JWT.SecretKey),
		security.SetAccessTokenCookieInterceptor(),
	)

	userService := services.NewUserAPI(cfg, userRepo, walletNonceRepo, emailPublisher, googleConfig, logger)
	userPath, userHandler := user.NewUserAccountAPIHandler(userService, interceptor)

	// Setup HTTP router
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Uniqora backend is live"))
	})
	mux.Handle(userPath, userHandler)

	// email-consumer-worker
	go worker.StartEmailWorker(cfg, logger)

	logger.Info("Server running on :8080")
	if err := http.ListenAndServe("0.0.0.0:8080", mux); err != nil {
		logger.Fatal("Server failed", zap.Error(err))
	}
}
