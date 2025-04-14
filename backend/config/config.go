package config

import (
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"log"
	"os"
)

type Config struct {
	PostgresSQL string       `mapstructure:"postgres_sql"`
	Email       EmailConfig  `mapstructure:"email"`
	RabbitMQ    RabbitConfig `mapstructure:"rabbitmq"`
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

func Load() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load .env file")
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
	return &cfg
}
