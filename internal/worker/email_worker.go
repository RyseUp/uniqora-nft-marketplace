package worker

import (
	"context"
	"github.com/RyseUp/uniqora-nft-marketplace/config"
	"go.uber.org/zap"
)

func StartEmailWorker(cfg *config.Config, logger *zap.Logger) {
	consumer, err := NewEmailConsumer(cfg)
	if err != nil {
		logger.Fatal("Failed to init email worker", zap.Error(err))
	}
	if err := consumer.Start(context.Background()); err != nil {
		logger.Fatal("Failed to run email worker", zap.Error(err))
	}
}
