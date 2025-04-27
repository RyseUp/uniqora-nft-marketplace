package config

import (
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"log"
	"os"
	"strings"
)

type Config struct {
	Email    EmailConfig  `mapstructure:"email"`
	RabbitMQ RabbitConfig `mapstructure:"rabbitmq"`
	JWT      JWTConfig    `mapstructure:"jwt"`
	Google   GoogleConfig `mapstructure:"google"`
}

type EmailConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	From     string `mapstructure:"from"`
	Password string `mapstructure:"password"`
}

type RabbitConfig struct {
	URL        string `mapstructure:"url"`
	EmailQueue string `mapstructure:"email_queue"`
}

type JWTConfig struct {
	SecretKey string `mapstructure:"secret_key"`
}

type GoogleConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Scopes       []string `mapstructure:"scopes"`
	RedirectURL  string   `mapstructure:"redirect_url"`
}

func Load() *Config {
	if os.Getenv("RAILWAY_ENVIRONMENT") == "" {
		// Only load .env in local dev
		if err := godotenv.Load(); err != nil {
			log.Fatal("Failed to load .env file")
		}
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Fatalf("config: %v", err)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("config unmarshal: %v", err)
	}

	// Chỉ override bằng ENV cho các field đặc biệt
	if envPwd := os.Getenv("EMAIL_PASSWORD"); envPwd != "" {
		cfg.Email.Password = envPwd
	}

	if envJWTSecret := os.Getenv("JWT_SECRET_KEY"); envJWTSecret != "" {
		cfg.JWT.SecretKey = envJWTSecret
	}

	if envClientID := os.Getenv("GOOGLE_CLIENT_ID"); envClientID != "" {
		cfg.Google.ClientID = envClientID
	}

	if envClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET"); envClientSecret != "" {
		cfg.Google.ClientSecret = envClientSecret
	}

	if envRedirectURL := os.Getenv("GOOGLE_REDIRECT_URL"); envRedirectURL != "" {
		cfg.Google.RedirectURL = envRedirectURL
	}

	if envScopes := os.Getenv("GOOGLE_SCOPES"); envScopes != "" {
		cfg.Google.Scopes = strings.Split(envScopes, ",")
	}

	return &cfg
}
