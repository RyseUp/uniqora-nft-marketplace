package security

import (
	"context"
	v1 "github.com/RyseUp/uniqora-nft-marketplace/api/user/v1"
	connect "github.com/bufbuild/connect-go"
	"net/http"
)

func SetAccessTokenCookieInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			resp, err := next(ctx, req)
			if err != nil {
				return nil, err
			}

			// Check if the response is from the UserLogin API
			if req.Spec().Procedure == v1.UserAccountAPI_UserLogin_FullMethodName {
				// Type assert the response to access the UserLoginResponse
				if loginResp, ok := resp.Any().(*v1.UserLoginResponse); ok && loginResp.AccessToken != "" {
					// Create a cookie for the access token
					cookie := &http.Cookie{
						Name:     "access_token",
						Value:    loginResp.AccessToken,
						Path:     "/",
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteStrictMode,
						Expires:  loginResp.ExpiresAt.AsTime(),
					}

					// Set the cookie in the response headers
					if headers := resp.Header(); headers != nil {
						headers.Add("Set-Cookie", cookie.String())
					}
				}
			}

			return resp, nil
		})
	})
}
