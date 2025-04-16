package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	v1 "github.com/RyseUp/uniqora-nft-marketplace/backend/api/user/v1"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/api/user/v1/v1connect"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/config"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/models"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/mq"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/repositories"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/security"
	"github.com/bufbuild/connect-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"time"
)

var (
	_ v1connect.UserAccountAPIHandler = &UserAPI{}
)

type UserAPI struct {
	cfg       *config.Config
	userRepo  repositories.User
	publisher *mq.EmailPublisher
}

func NewUserAPI(
	cfg *config.Config,
	userRepo repositories.User,
	publisher *mq.EmailPublisher,
) *UserAPI {
	return &UserAPI{
		cfg:       cfg,
		userRepo:  userRepo,
		publisher: publisher,
	}
}

func EncryptPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

func GenerateVerifyCode() (string, error) {
	n := make([]byte, 3)
	_, err := rand.Read(n)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", int(n[0])<<8|int(n[1])), nil
}

func (s *UserAPI) UserSignup(ctx context.Context, c *connect.Request[v1.UserSignupRequest]) (*connect.Response[v1.UserSignupResponse], error) {
	var (
		req      = c.Msg
		username = req.GetUsername()
		email    = req.GetEmail()
		password = req.GetPassword()
	)

	// verify existed user account
	existUser, err := s.userRepo.GetUserByUserEmail(ctx, email)
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get exist user: %w", err))
	}
	if existUser != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("user email_center already exist"))
	}

	// handle spam register
	currentTime := time.Now()
	userRegis, err := s.userRepo.GetLastUserRegisterByEmail(ctx, email)
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get last user register email_center: %w", err))
	default:
		if currentTime.Before(userRegis.ExpiredAt) {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("you are limited to a certain number of requests"))
		}
		if userRegis.Status == models.UserRegisterStatusCompleted {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("email_center has been used in this system"))
		}
	}

	// create new user register
	encryptedPassword := EncryptPassword(password)
	newUserRegister, err := s.createUserRegister(ctx, username, email, encryptedPassword)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create new user register: %w", err))
	}

	return connect.NewResponse(&v1.UserSignupResponse{
		PendingUserName: newUserRegister.UserName,
		ExpiredAt:       timestamppb.New(time.Now().Add(24 * time.Hour)),
	}), nil
}

func (s *UserAPI) createUserRegister(ctx context.Context, username, email, password string) (*models.UserRegister, error) {
	verificationCode, err := GenerateVerifyCode()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error generate verification code: %w", err))
	}

	expiredAt := time.Now().Add(60 * time.Second)
	newUserRegister, err := s.userRepo.CreateUserRegister(ctx, &models.UserRegister{
		UserName:   username,
		Email:      email,
		Password:   password,
		VerifyCode: verificationCode,
		ExpiredAt:  expiredAt,
		Status:     models.UserRegisterStatusRequested,
	})

	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create new user register: %w", err))
	}

	// send email_center by message queue
	if err = s.publisher.PublishVerificationEmai(ctx, email, newUserRegister.VerifyCode); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send email_center verifycode: %w", err))
	}

	return newUserRegister, nil
}

func (s *UserAPI) UserCompleteSignup(ctx context.Context, c *connect.Request[v1.UserCompleteSignupRequest]) (*connect.Response[v1.UserCompleteSignupResponse], error) {
	var (
		req              = c.Msg
		email            = req.GetEmail()
		verificationCode = req.GetVerificationCode()
	)

	userRegister, err := s.userRepo.GetLastUserRegisterByEmail(ctx, email)
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("not found register info: %w", err))
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user register info: %w", err))
	}

	if userRegister.Status == models.UserRegisterStatusCompleted {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("email has been used in this system"))
	}

	currentTime := time.Now()
	timeExpire := userRegister.ExpiredAt
	if timeExpire.Before(currentTime) {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("user registration has expired"))
	}

	if verificationCode != userRegister.VerifyCode {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("verification code is invalid"))
	}

	_, err = s.userRepo.GetUserByUserEmail(ctx, email)
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user email_center: %w", err))
	}

	userID := uuid.New().String()

	newUser := &models.User{
		UserID:   userID,
		UserName: userRegister.UserName,
		Email:    userRegister.Email,
		Password: userRegister.Password,
		Provider: models.AuthProviderLocal,
	}
	_, err = s.userRepo.CompleteUserRegister(ctx, userRegister, newUser)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to complete user register: %w", err))
	}

	if err = s.publisher.PublishWelcomeEmail(ctx, email, newUser.UserName); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send welcome email_center: %w", err))
	}

	return connect.NewResponse(&v1.UserCompleteSignupResponse{
		Message: "completed sign up",
	}), nil
}

func (s *UserAPI) UserResendSignup(ctx context.Context, c *connect.Request[v1.UserResendSignupRequest]) (*connect.Response[v1.UserResendSignupResponse], error) {
	var (
		req   = c.Msg
		email = req.GetEmail()
	)

	currentTime := time.Now()
	userRegis, err := s.userRepo.GetLastUserRegisterByEmail(ctx, email)
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user didn't have any previous registrations"))
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get last user register email_center: %w", err))
	default:
		if currentTime.After(userRegis.ExpiredAt) {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("you are limited to a certain number of requests"))
		}
		if userRegis.Status == models.UserRegisterStatusCompleted {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("email has been used in this system"))
		}
	}

	_, err = s.createUserRegister(ctx, userRegis.UserName, email, userRegis.Password)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create new user register: %w", err))
	}

	return connect.NewResponse(&v1.UserResendSignupResponse{
		Message:   "complete-resend-sign-up",
		ExpiredAt: timestamppb.New(time.Now().Add(24 * time.Hour)),
	}), nil
}

func (s *UserAPI) UserLogin(ctx context.Context, c *connect.Request[v1.UserLoginRequest]) (*connect.Response[v1.UserLoginResponse], error) {
	var (
		req      = c.Msg
		email    = req.GetEmail()
		password = req.GetPassword()
	)

	user, err := s.userRepo.GetUserByUserEmail(ctx, email)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user information: %w", err))
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid credentials"))
	}

	accessToken, exp, err := security.GenerateJWT(user.UserID, s.cfg.JWT.SecretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("generate jwt: %w", err))
	}

	sessionID := uuid.New().String()
	refreshToken, _, err := security.GenerateRefreshToken(sessionID, s.cfg.JWT.SecretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("generate refresh token: %w", err))
	}

	currentTime := time.Now()
	expiredAt := currentTime.Add(7 * 24 * time.Hour)

	newUserSession := &models.UserSession{
		SessionID:    sessionID,
		UserID:       user.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserAgent:    c.Header().Get("User-Agent"),
		IPAddress:    "",
		ExpiresAt:    expiredAt,
	}

	if err := s.userRepo.CreateUserSession(ctx, newUserSession); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create user session: %w", err))
	}

	return connect.NewResponse(&v1.UserLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    timestamppb.New(exp),
	}), nil
}
