package repositories

import (
	"context"
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/models"
	"gorm.io/gorm"
)

type User interface {
	CreateNewUser(ctx context.Context, user *models.User) error
	GetUserByUserEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByUserID(ctx context.Context, userID string) (*models.User, error)
	UpdateUserProfile(ctx context.Context, user *models.User) error
	UpdateUserPasswordByUserID(ctx context.Context, userID, newPassword string) error
	GetUserByWalletAddress(ctx context.Context, walletAddress string) (*models.User, error)
	UserRegister
	UserSession
}

var _ User = &UserStore{}

type UserStore struct {
	db *gorm.DB
}

func NewUserStore(db *gorm.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) CreateNewUser(ctx context.Context, user *models.User) error {
	return s.db.WithContext(ctx).Model(&models.User{}).Create(user).Error
}

func (s *UserStore) GetUserByUserEmail(ctx context.Context, email string) (*models.User, error) {
	var res models.User
	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("email = ?", email).
		First(&res)

	if err.Error != nil {
		return nil, fmt.Errorf("get detail user failed: %w", err.Error)
	}

	return &res, nil
}

func (s *UserStore) GetUserByUserID(ctx context.Context, userID string) (*models.User, error) {
	var res models.User
	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("user_id = ?", userID).
		First(&res).
		Error

	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (s *UserStore) UpdateUserProfile(ctx context.Context, user *models.User) error {
	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("user_id  = ?", user.UserID).
		Updates(map[string]interface{}{
			"user_name":  user.UserName,
			"avatar_url": user.AvatarURL,
		}).
		Error

	if err != nil {
		return err
	}

	return nil
}

func (s *UserStore) UpdateUserPasswordByUserID(ctx context.Context, userID, newPassword string) error {
	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"password": newPassword,
		}).Error

	if err != nil {
		return err
	}

	return nil
}

func (s *UserStore) GetUserByWalletAddress(ctx context.Context, walletAddress string) (*models.User, error) {
	var res models.User
	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("wallet_address = ?", walletAddress).
		First(&res).
		Error

	if err != nil {
		return nil, err
	}

	return &res, nil
}
