package models

import (
	"database/sql"
	"time"
)

type User struct {
	ID            int64          `gorm:"type:bigint;autoIncrement"`
	UserID        string         `gorm:"type:text;primaryKey;uniqueIndex" json:"user_id"`
	UserName      string         `gorm:"type:text;uniqueIndex" json:"user_name"`
	Email         string         `gorm:"type:text;uniqueIndex" json:"email_center"`
	Password      string         `gorm:"type:text" json:"password"`
	GoogleID      sql.NullString `gorm:"type:text;uniqueIndex" json:"google_id"`
	WalletAddress sql.NullString `gorm:"type:text" json:"wallet_address"`
	Provider      AuthProvider   `gorm:"type:text" json:"provider"`
	AvatarURL     string         `gorm:"type:text" json:"avatar_url"`
	CreatedAt     time.Time      `gorm:"type:timestamp" json:"created_at"`
	UpdatedAt     time.Time      `gorm:"type:timestamp" json:"updated_at"`
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

type UserSession struct {
	ID           int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	SessionID    string    `gorm:"type:text;uniqueIndex" json:"session_id"`
	UserID       string    `gorm:"type:text;not null" json:"user_id"`
	AccessToken  string    `gorm:"type:text" json:"access_token"`
	RefreshToken string    `gorm:"type:text;not null" json:"refresh_token"`
	UserAgent    string    `gorm:"type:text" json:"user_agent"`
	IPAddress    string    `gorm:"type:text" json:"ip_address"`
	ExpiresAt    time.Time `gorm:"type:timestamp;not null" json:"expires_at"`
	CreatedAt    time.Time `gorm:"type:timestamp;not null" json:"created_at"`
}

func (UserSession) TableName() string {
	return "user_sessions"
}

type WalletNonce struct {
	WalletAddress string    `gorm:"type:text" json:"wallet_address"`
	Nonce         string    `gorm:"primaryKey; type:text" json:"nonce"`
	ExpiredAt     time.Time `gorm:"type:timestamp; not null" json:"expired_at"`
	Used          bool      `gorm:"type:bool;default:false" json:"used"`
	Message       string    `gorm:"type:text" json:"message"`
}

func (WalletNonce) TableName() string {
	return "wallet_nonce"
}
