package repositories

import (
	"context"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/models"
)

type UserSession interface {
	CreateUserSession(ctx context.Context, session *models.UserSession) error
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*models.UserSession, error)
	DeleteSessionByRefreshToken(ctx context.Context, refreshToken string) error
	DeleteUserSessionByAccessToken(ctx context.Context, accessToken string) error
}

func (s *UserStore) CreateUserSession(ctx context.Context, session *models.UserSession) error {
	return s.db.WithContext(ctx).
		Model(&models.UserSession{}).
		Create(session).
		Error
}

func (s *UserStore) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*models.UserSession, error) {
	var res models.UserSession
	err := s.db.WithContext(ctx).
		Model(&models.UserSession{}).
		Where("refresh_token = ?", refreshToken).
		First(&res).
		Error

	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (s *UserStore) DeleteSessionByRefreshToken(ctx context.Context, refreshToken string) error {
	return s.db.WithContext(ctx).
		Where("refresh_token = ?", refreshToken).
		Delete(&models.UserSession{}).
		Error
}

func (s *UserStore) DeleteUserSessionByAccessToken(ctx context.Context, accessToken string) error {
	return s.db.WithContext(ctx).
		Where("access_token = ?", accessToken).
		Delete(&models.UserSession{}).
		Error
}
