package email_center

import "github.com/RyseUp/uniqora-nft-marketplace/internal/email_center/types"

type Message struct {
	Type    types.EmailType   `json:"type"`
	Email   string            `json:"email_center"`
	Subject string            `json:"subject,omitempty"`
	Data    map[string]string `json:"data"`
}

func NewVerificationEmail(email, code string) Message {
	return Message{
		Type:  types.TypeVerification,
		Email: email,
		Data: map[string]string{
			"code": code,
		},
	}
}

func NewWelcomeEmail(email, name string) Message {
	return Message{
		Type:  types.TypeWelcome,
		Email: email,
		Data: map[string]string{
			"name": name,
		},
	}
}

func NewAccountCreatedEmail(email, name string) Message {
	return Message{
		Type:  types.TypeAccountCreated,
		Email: email,
		Data: map[string]string{
			"name": name,
		},
	}
}

func NewPasswordResetEmail(email, code string) Message {
	return Message{
		Type:  types.TypePasswordReset,
		Email: email,
		Data: map[string]string{
			"code": code,
		},
	}
}

func NewNotificationEmail(email, subject, message string) Message {
	return Message{
		Type:    types.TypeNotification,
		Email:   email,
		Subject: subject,
		Data: map[string]string{
			"message": message,
		},
	}
}
