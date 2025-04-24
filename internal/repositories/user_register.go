package repositories

import (
	"context"
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/models"
	"gorm.io/gorm"
)

type UserRegister interface {
	GetLastUserRegisterByEmail(ctx context.Context, email string) (*models.UserRegister, error)
	CreateUserRegister(ctx context.Context, newUserRegister *models.UserRegister) (*models.UserRegister, error)
	CompleteUserRegister(ctx context.Context, userRegister *models.UserRegister, newUser *models.User) (*models.User, error)
}

func (s *UserStore) GetLastUserRegisterByEmail(ctx context.Context, email string) (*models.UserRegister, error) {
	var userRegister models.UserRegister
	result := s.db.
		Model(&models.UserRegister{}).
		WithContext(ctx).
		Where("email = ?", email).
		Last(&userRegister)
	if result.Error != nil {
		return nil, fmt.Errorf("get detail user register failed: %w", result.Error)
	}
	return &userRegister, nil
}

func (s *UserStore) CreateUserRegister(ctx context.Context, newUserRegister *models.UserRegister) (*models.UserRegister, error) {
	return newUserRegister, s.db.Model(&models.UserRegister{}).WithContext(ctx).Create(newUserRegister).Error
}

func (s *UserStore) CompleteUserRegister(ctx context.Context, userRegister *models.UserRegister, newUser *models.User) (*models.User, error) {
	return newUser, s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.UserRegister{}).
			Where("id = ?", userRegister.ID).
			Where("status = ?", models.UserRegisterStatusRequested).
			Update("status", models.UserRegisterStatusCompleted).
			Error; err != nil {
			return err
		}

		if err := tx.Create(newUser).Error; err != nil {
			return err
		}

		return nil
	})
}
