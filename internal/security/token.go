package security

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var (
	jwtExpiry     = time.Hour * 1
	refreshExpiry = time.Hour * 24 * 7
)

func GenerateJWT(userID, jwtSecret string) (string, time.Time, error) {
	exp := time.Now().Add(jwtExpiry)
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(jwtSecret))
	return ss, exp, err
}

func GenerateRefreshToken(userID, jwtSecret string) (string, time.Time, error) {
	exp := time.Now().Add(refreshExpiry)
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(jwtSecret))
	return ss, exp, err
}

func ParseToken(tokenStr, jwtSecret string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
}
