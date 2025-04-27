package config

import (
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"log"
	"os"
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
}

func Load() *Config {
	if os.Getenv("RAILWAY_ENVIRONMENT") == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("No local .env file found, skipping (expected in production)")
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

	viper.AutomaticEnv()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("config unmarshal: %v", err)
	}

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
	return &cfg
}
