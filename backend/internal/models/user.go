package models

import "time"

type User struct {
	ID            int64        `gorm:"type:bigint;autoIncrement"`
	UserID        string       `gorm:"type:text;primaryKey;uniqueIndex" json:"user_id"`
	UserName      string       `gorm:"type:text;uniqueIndex" json:"user_name"`
	Email         string       `gorm:"type:text;uniqueIndex" json:"email_center"`
	Password      string       `gorm:"type:text" json:"password"`
	GoogleID      string       `gorm:"type:text" json:"google_id"`
	WalletAddress string       `gorm:"type:text" json:"wallet_address"`
	Provider      AuthProvider `gorm:"type:text" json:"provider"`
	AvatarURL     string       `gorm:"type:text" json:"avatar_url"`
	CreatedAt     time.Time    `gorm:"type:timestamp" json:"created_at"`
	UpdatedAt     time.Time    `gorm:"type:timestamp" json:"updated_at"`
}

func (User) TableName() string {
	return "users"
}

type AuthProvider string

const (
	AuthProviderLocal  AuthProvider = "local"
	AuthProviderGoogle AuthProvider = "google"
	AuthProviderWallet AuthProvider = "wallet"
)

type RefreshToken struct {
	ID        int64  `gorm:"type:bigint;primaryKey;autoIncrement" json:"id"`
	Token     string `gorm:"type:text;uniqueIndex;not null" json:"token"`
	UserID    string `gorm:"type:text;not null" json:"user_id"`
	ExpiredAt string `gorm:"type:timestamp; not null" json:"expired_at"`
	CreatedAt string `gorm:"type:timestamp; not null" json:"created_at"`
}

func (RefreshToken) TableName() string {
	return "refresh_token"
}
