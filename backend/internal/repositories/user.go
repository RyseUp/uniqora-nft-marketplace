package repositories

import (
	"context"
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/models"
	"gorm.io/gorm"
)

type User interface {
	GetUserByUserEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByUserID(ctx context.Context, userID string) (*models.User, error)
	UpdateUserProfile(ctx context.Context, user *models.User) error
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

func (s *UserStore) GetUserByUserEmail(ctx context.Context, email string) (*models.User, error) {
	var res models.User
	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("email = ?", email).
		First(&res).
		Error

	if err != nil {
		return nil, fmt.Errorf("failed to get user by email_center: %w", err)
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
