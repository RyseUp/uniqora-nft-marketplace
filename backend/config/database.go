package config

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

var DB *gorm.DB

func ConnectDatabase(cfg *Config, models ...interface{}) (*gorm.DB, error) {
	dsn := cfg.PostgresSQL
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	if len(models) > 0 {
		if err := db.AutoMigrate(models...); err != nil {
			return nil, err
		}
	}
	DB = db
	log.Println("database: connected")
	return db, nil
}
