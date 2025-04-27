package auth

import (
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log"
)

type GoogleAuthResponse struct {
	Sub   string `json:"sub"`
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func NewGoogleOAuthConfig(cfg *config.GoogleConfig) (*oauth2.Config, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("missing Google OAuth2 client ID or secret")
	}
	if len(cfg.Scopes) == 0 {
		log.Fatal("missing Google OAuth2 scopes")
		return nil, fmt.Errorf("missing Google OAuth2 scopes")
	}

	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}, nil
}
