package models

import "time"

type UserRegister struct {
	ID         int64              `gorm:"type:bigint;primaryKey;autoIncrement" json:"id"`
	UserName   string             `gorm:"type:text;index" json:"user_name"`
	Email      string             `gorm:"type:text;index" json:"email_center"`
	Password   string             `gorm:"type:text" json:"password"`
	VerifyCode string             `gorm:"type:text" json:"verify_code"`
	CreatedAt  time.Time          `gorm:"type:timestamp" json:"created_at"`
	ExpiredAt  time.Time          `gorm:"type:timestamp" json:"expired_at"`
	Status     UserRegisterStatus `gorm:"type:smallint" json:"status"`
}

func (UserRegister) TableName() string {
	return "user_register"
}

type UserRegisterStatus int

const (
	UserRegisterStatusUnknown   UserRegisterStatus = 0
	UserRegisterStatusRequested UserRegisterStatus = 1
	UserRegisterStatusCompleted UserRegisterStatus = 2
)
