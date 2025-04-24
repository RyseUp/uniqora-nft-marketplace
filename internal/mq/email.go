package mq

import (
	"context"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/email_center"
)

type EmailPublisher struct {
	publisher *Publisher
	queueName string
}

func NewEmailPublisher(publisher *Publisher, queueName string) *EmailPublisher {
	return &EmailPublisher{
		publisher: publisher,
		queueName: queueName,
	}
}

func (p *EmailPublisher) PublishEmail(ctx context.Context, msg email_center.Message) error {
	return p.publisher.Publish(ctx, msg)
}

func (p *EmailPublisher) PublishVerificationEmai(ctx context.Context, email, code string) error {
	msg := email_center.NewVerificationEmail(email, code)
	return p.PublishEmail(ctx, msg)
}

func (p *EmailPublisher) PublishWelcomeEmail(ctx context.Context, email, name string) error {
	msg := email_center.NewWelcomeEmail(email, name)
	return p.PublishEmail(ctx, msg)
}

func (p *EmailPublisher) PublishAccountCreatedEmail(ctx context.Context, email, name string) error {
	msg := email_center.NewAccountCreatedEmail(email, name)
	return p.PublishEmail(ctx, msg)
}

func (p *EmailPublisher) PublishPasswordResetEmail(ctx context.Context, email, code string) error {
	msg := email_center.NewPasswordResetEmail(email, code)
	return p.PublishEmail(ctx, msg)
}

func (p *EmailPublisher) PublishNotificationEmail(ctx context.Context, email, subject, message string) error {
	msg := email_center.NewNotificationEmail(email, subject, message)
	return p.PublishEmail(ctx, msg)
}
