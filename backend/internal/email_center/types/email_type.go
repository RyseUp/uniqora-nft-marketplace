package types

type EmailType string

const (
	TypeVerification   EmailType = "verification"
	TypeWelcome        EmailType = "welcome"
	TypeAccountCreated EmailType = "account_created"
	TypePasswordReset  EmailType = "password_reset"
	TypeNotification   EmailType = "notification"
)
