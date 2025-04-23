package repositories

import (
	"context"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/models"
	"gorm.io/gorm"
)

type WalletNonce interface {
	CreateNewNonce(ctx context.Context, newNonce *models.WalletNonce) error
	UserGetNonceByNonce(ctx context.Context, nonce string) (*models.WalletNonce, error)
	MarkNonceUsed(ctx context.Context, walletAddress, nonce string) error
}

var _ WalletNonce = &WalletNonceStore{}

type WalletNonceStore struct {
	db *gorm.DB
}

func NewWalletNonce(db *gorm.DB) *WalletNonceStore {
	return &WalletNonceStore{db: db}
}

func (w *WalletNonceStore) CreateNewNonce(ctx context.Context, newNonce *models.WalletNonce) error {
	return w.db.WithContext(ctx).Model(&models.WalletNonce{}).Create(newNonce).Error
}

func (w *WalletNonceStore) UserGetNonceByNonce(ctx context.Context, nonce string) (*models.WalletNonce, error) {
	var res models.WalletNonce
	err := w.db.WithContext(ctx).
		Model(&models.WalletNonce{}).
		Where("nonce = ?", nonce).
		First(&res).
		Error

	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (w *WalletNonceStore) MarkNonceUsed(ctx context.Context, walletAddress, nonce string) error {
	return w.db.WithContext(ctx).
		Model(&models.WalletNonce{}).
		Where("wallet_address = ?", walletAddress).
		Where("nonce = ?", nonce).
		Update("used", true).
		Error
}
