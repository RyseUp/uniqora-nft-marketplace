package email_center

import (
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/config"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/email_center/template"
	"gopkg.in/gomail.v2"
	"log"
)

type Service interface {
	Send(msg Message) error
	SendVerificationEmail(email, code string) error
	SendWelcomeEmail(email, name string) error
	SendAccountCreatedEmail(email, name string) error
	SendPasswordResetEmail(email, code string) error
	SendNotificationEmail(email, subject, message string) error
}

var _ Service = &EmailService{}

type EmailService struct {
	cfg             *config.Config
	templateManager *template.Manager
}

func NewEmailService(cfg *config.Config, templateManager *template.Manager) *EmailService {
	return &EmailService{
		cfg:             cfg,
		templateManager: templateManager,
	}
}

func (s *EmailService) Send(msg Message) error {
	body, err := s.templateManager.RenderEmail(msg.Type, msg.Data)
	if err != nil {
		return err
	}

	subject := msg.Subject
	if subject == "" {
		subject = s.templateManager.GetDefaultSubject(msg.Type)
	}

	return s.sendMail(msg.Email, subject, body)
}

func (s *EmailService) sendMail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.cfg.Email.From)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	d := gomail.NewDialer(s.cfg.Email.Host, s.cfg.Email.Port, s.cfg.Email.From, s.cfg.Email.Password)
	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email_center: %w", err)
	}

	log.Printf("Email sent successfully to %s with subject: %s", to, subject)
	return nil
}

func (s *EmailService) SendVerificationEmail(email, code string) error {
	msg := NewVerificationEmail(email, code)
	if err := s.Send(msg); err != nil {
		return fmt.Errorf("failed to send verification email_center: %w", err)
	}
	return nil
}

func (s *EmailService) SendWelcomeEmail(email, name string) error {
	msg := NewWelcomeEmail(email, name)
	if err := s.Send(msg); err != nil {
		return fmt.Errorf("failed to send welcome email_center: %w", err)
	}
	return nil
}

func (s *EmailService) SendAccountCreatedEmail(email, name string) error {
	msg := NewAccountCreatedEmail(email, name)
	if err := s.Send(msg); err != nil {
		return fmt.Errorf("failed to send create account email_center: %w", err)
	}
	return nil
}

func (s *EmailService) SendPasswordResetEmail(email, code string) error {
	msg := NewPasswordResetEmail(email, code)
	if err := s.Send(msg); err != nil {
		return fmt.Errorf("failed to send email_center reset password: %w", err)
	}
	return nil
}

func (s *EmailService) SendNotificationEmail(email, subject, message string) error {
	msg := NewNotificationEmail(email, subject, message)
	if err := s.Send(msg); err != nil {
		return fmt.Errorf("failed to send notification email_center: %w", err)
	}
	return nil
}
