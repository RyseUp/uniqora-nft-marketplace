package services

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	v1 "github.com/RyseUp/uniqora-nft-marketplace/backend/api/user/v1"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/api/user/v1/v1connect"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/auth"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/config"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/mapper"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/models"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/mq"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/repositories"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/security"
	"github.com/bufbuild/connect-go"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"net/http"
	"time"
)

var (
	_ v1connect.UserAccountAPIHandler = &UserAPI{}
)

type UserAPI struct {
	cfg          *config.Config
	userRepo     repositories.User
	publisher    *mq.EmailPublisher
	googleClient *oauth2.Config
	logger       *zap.Logger
}

func NewUserAPI(
	cfg *config.Config,
	userRepo repositories.User,
	publisher *mq.EmailPublisher,
	googleClient *oauth2.Config,
	logger *zap.Logger,
) *UserAPI {
	return &UserAPI{
		cfg:          cfg,
		userRepo:     userRepo,
		publisher:    publisher,
		googleClient: googleClient,
		logger:       logger,
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
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user email: %w", err))
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
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send welcome email: %w", err))
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
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get last user register email: %w", err))
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
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate jwt: %w", err))
	}

	sessionID := uuid.New().String()
	refreshToken, _, err := security.GenerateRefreshToken(sessionID, s.cfg.JWT.SecretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate refresh token: %w", err))
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

func (s *UserAPI) UserRefreshToken(ctx context.Context, c *connect.Request[v1.UserRefreshTokenRequest]) (*connect.Response[v1.UserRefreshTokenResponse], error) {
	req := c.Msg
	oldToken := req.GetRefreshToken()

	tokenInfo, err := s.userRepo.GetSessionByRefreshToken(ctx, oldToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid refresh token"))
	}

	currentTime := time.Now()
	if currentTime.After(tokenInfo.ExpiresAt) {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("refresh token expired"))
	}

	accessToken, exp, err := security.GenerateJWT(tokenInfo.UserID, tokenInfo.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate jwt: %w", err))
	}

	newRefreshToken, _, err := security.GenerateRefreshToken(tokenInfo.UserID, tokenInfo.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate refresh token: %w", err))
	}

	if err = s.userRepo.DeleteSessionByRefreshToken(ctx, oldToken); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete old refresh token"))
	}

	err = s.userRepo.CreateUserSession(ctx, &models.UserSession{
		RefreshToken: newRefreshToken,
		UserID:       tokenInfo.UserID,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate new refresh token: %w", err))
	}

	return connect.NewResponse(&v1.UserRefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    timestamppb.New(exp),
	}), nil
}

func (s *UserAPI) UserLogout(ctx context.Context, c *connect.Request[v1.UserLogoutRequest]) (*connect.Response[v1.UserLogoutResponse], error) {
	_, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user_id not found"))
	}
	cookieHeader := c.Header().Get("Cookie")
	accessToken := security.ExtractTokenFromCookie(cookieHeader)
	if accessToken == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing access token"))
	}

	if err := s.userRepo.DeleteUserSessionByAccessToken(ctx, accessToken); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete user session: %w", err))
	}

	cookies := []*http.Cookie{
		{
			Name:     "access_token",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
		{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Expires:  time.Unix(0, 0),
		},
	}

	for _, cookie := range cookies {
		c.Header().Add("Set-Cookie", cookie.String())
	}

	return connect.NewResponse(&v1.UserLogoutResponse{
		Message: "user-logout-success",
	}), nil
}

func (s *UserAPI) UserUpdateProfile(ctx context.Context, c *connect.Request[v1.UserUpdateProfileRequest]) (*connect.Response[v1.UserUpdateProfileResponse], error) {
	var (
		req       = c.Msg
		username  = req.GetUsername()
		avatarUrl = req.GetAvatarUrl()
	)

	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user_id not found"))
	}

	userInfo, err := s.userRepo.GetUserByUserID(ctx, userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user by user id: %w", err))
	}

	// update user profile
	userInfo.UserName = username
	userInfo.AvatarURL = avatarUrl

	if err := s.userRepo.UpdateUserProfile(ctx, userInfo); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user profile: %w", err))
	}

	return connect.NewResponse(&v1.UserUpdateProfileResponse{
		Message: "update-user-profile-success",
	}), nil
}

func (s *UserAPI) UserGetSelfProfile(ctx context.Context, c *connect.Request[v1.UserGetSelfProfileRequest]) (*connect.Response[v1.UserGetSelfProfileResponse], error) {
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user_id not found"))
	}

	userInfo, err := s.userRepo.GetUserByUserID(ctx, userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user by user-id: %w", err))
	}

	return connect.NewResponse(&v1.UserGetSelfProfileResponse{
		Data: mapper.ModelToProtoUserInfo(userInfo),
	}), nil
}

func (s *UserAPI) UserChangePassword(ctx context.Context, c *connect.Request[v1.UserChangePasswordRequest]) (*connect.Response[v1.UserChangePasswordResponse], error) {
	var (
		req         = c.Msg
		oldPassword = req.GetOldPassword()
		newPassword = req.GetNewPassword()
	)

	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("unauthorized"))
	}

	userInfo, err := s.userRepo.GetUserByUserID(ctx, userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user infomatinon: %w", err))
	}

	if err = bcrypt.CompareHashAndPassword([]byte(userInfo.Password), []byte(oldPassword)); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid current password"))
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to hash new password: %w", err))
	}

	if err = s.userRepo.UpdateUserPasswordByUserID(ctx, userID, string(newHashedPassword)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update new password: %w", err))
	}

	return connect.NewResponse(&v1.UserChangePasswordResponse{
		Message: "user-update-password-success",
	}), nil
}

func (s *UserAPI) ExchangeGoogleCode(ctx context.Context, c *connect.Request[v1.ExchangeGoogleCodeRequest]) (*connect.Response[v1.UserGoogleAuthResponse], error) {
	var (
		req  = c.Msg
		code = req.GetCode()
	)

	token, err := s.googleClient.Exchange(ctx, code)
	if err != nil {
		s.logger.Warn("failed to exchange authorization code", zap.Error(err))
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("failed to exchange code: %w", err))
	}

	authReq := &connect.Request[v1.UserGoogleAuthRequest]{
		Msg: &v1.UserGoogleAuthRequest{AccessToken: token.AccessToken},
	}
	return s.UserGoogleAuth(ctx, authReq)
}

func (s *UserAPI) UserGoogleAuth(ctx context.Context, c *connect.Request[v1.UserGoogleAuthRequest]) (*connect.Response[v1.UserGoogleAuthResponse], error) {
	var (
		req               = c.Msg
		googleAccessToken = req.GetAccessToken()
	)

	client := s.googleClient.Client(ctx, &oauth2.Token{AccessToken: googleAccessToken})
	reps, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo") // <-- incase the user info don't need to be realtime can decode and verify via the GoogleIdToken
	if err != nil || reps.StatusCode != 200 {
		s.logger.Warn("failed to fetch Google user info", zap.Error(err))
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("failed to fetch user info"))
	}
	defer reps.Body.Close()

	var googleFetchUserInfo auth.GoogleAuthResponse
	if err := json.NewDecoder(reps.Body).Decode(&googleFetchUserInfo); err != nil {
		s.logger.Warn("failed to decode user info", zap.Error(err))
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("failed to decode user info: %w", err))
	}

	if googleFetchUserInfo.Email == "" || (googleFetchUserInfo.Sub == "" && googleFetchUserInfo.ID == "") {
		s.logger.Warn("missing email or sub in user info")
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid user info from Google"))
	}

	// find or create new user
	googleID := googleFetchUserInfo.Sub
	if googleID == "" {
		googleID = googleFetchUserInfo.ID
	}
	userInfo, err := s.userRepo.GetUserByUserEmail(ctx, googleFetchUserInfo.Email)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		userInfo = &models.User{
			UserID:   uuid.New().String(),
			UserName: googleFetchUserInfo.Name,
			Email:    googleFetchUserInfo.Email,
			Password: "",
			GoogleID: sql.NullString{String: googleID, Valid: true},
			Provider: models.AuthProviderGoogle,
		}
		if err := s.userRepo.CreateNewUser(ctx, userInfo); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create new user: %w", err))
		}

		if err = s.publisher.PublishWelcomeEmail(ctx, userInfo.Email, userInfo.UserName); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send welcome email: %w", err))
		}
		s.logger.Info("created new user via Google auth", zap.String("email", userInfo.Email))
	} else if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	accessToken, exp, err := security.GenerateJWT(userInfo.UserID, s.cfg.JWT.SecretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate access token: %w", err))
	}

	sessionID := uuid.New().String()
	refreshToken, _, err := security.GenerateRefreshToken(sessionID, s.cfg.JWT.SecretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate refresh token: %w", err))
	}

	newUserSession := &models.UserSession{
		SessionID:    sessionID,
		UserID:       userInfo.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserAgent:    c.Header().Get("User-Agent"),
		IPAddress:    "",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	if err = s.userRepo.CreateUserSession(ctx, newUserSession); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create new user session: %w", err))
	}

	s.logger.Info("Google auth successful", zap.String("user_id", userInfo.UserID))
	return connect.NewResponse(&v1.UserGoogleAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    timestamppb.New(exp),
	}), nil
}

func (s *UserAPI) UserMetaMaskAuth(ctx context.Context, c *connect.Request[v1.UserMetaMaskAuthRequest]) (*connect.Response[v1.UserMetaMaskAuthResponse], error) {
	var (
		req           = c.Msg
		walletAddress = req.GetWalletAddress()
		message       = req.GetMessage()
		signature     = req.GetSignature()
	)

	// verify signature
	validSignature, err := security.VerifyMetaMaskSignature(walletAddress, message, signature)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("failed to valid signature: %w", err))
	}

	if !validSignature {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid signature"))
	}

	userInfo, err := s.userRepo.GetUserByWalletAddress(ctx, walletAddress)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		userInfo = &models.User{
			UserID:        uuid.New().String(),
			UserName:      "User_" + walletAddress[2:8],
			WalletAddress: sql.NullString{String: walletAddress, Valid: true},
			Provider:      models.AuthProviderWallet,
		}
		if err := s.userRepo.CreateNewUser(ctx, userInfo); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create new user: %w", err))
		}
	} else if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	accessToken, exp, err := security.GenerateJWT(userInfo.UserID, s.cfg.JWT.SecretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create accessToken: %w", err))
	}

	sessionID := uuid.New().String()
	refreshToken, _, err := security.GenerateRefreshToken(sessionID, s.cfg.JWT.SecretKey)

	newSession := &models.UserSession{
		SessionID:    sessionID,
		UserID:       userInfo.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserAgent:    c.Header().Get("User-Agent"),
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	if err := s.userRepo.CreateUserSession(ctx, newSession); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create user session: %w", err))
	}

	return connect.NewResponse(&v1.UserMetaMaskAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    timestamppb.New(exp),
	}), nil
}
