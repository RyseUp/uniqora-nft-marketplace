package security

import (
	"context"
	"errors"
	v1 "github.com/RyseUp/uniqora-nft-marketplace/backend/api/user/v1"
	"github.com/bufbuild/connect-go"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

func extractTokenFromCookie(cookieHeader string) string {
	for _, cookie := range strings.Split(cookieHeader, ";") {
		cookie = strings.TrimSpace(cookie)
		if strings.HasPrefix(cookie, "access_token=") {
			return strings.TrimPrefix(cookie, "access_token=")
		}
	}
	return ""
}

func AuthInterceptor(secretKey string) connect.UnaryInterceptorFunc {
	publicEndpoints := map[string]bool{
		v1.UserAccountAPI_UserLogin_FullMethodName:  true,
		v1.UserAccountAPI_UserSignup_FullMethodName: true,
	}

	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			if publicEndpoints[request.Spec().Procedure] {
				return next(ctx, request)
			}

			cookieHeader := request.Header().Get("Cookie")
			tokenString := extractTokenFromCookie(cookieHeader)
			if tokenString == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing access token"))
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("invalid singing method")
				}
				return []byte(secretKey), nil
			})
			if err != nil || !token.Valid {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				userID, ok := claims["user_id"].(string)
				if !ok {
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid token claims"))
				}
				ctx = context.WithValue(ctx, "user_id", userID)
			} else {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid token claims"))
			}

			return next(ctx, request)
		})
	})
}
