package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/email_center"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/email_center/template"
	"log"

	"github.com/RyseUp/uniqora-nft-marketplace/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

type EmailConsumer struct {
	cfg          *config.Config
	conn         *amqp.Connection
	emailService email_center.Service
}

func NewEmailConsumer(cfg *config.Config) (*EmailConsumer, error) {
	conn, err := amqp.Dial(cfg.RabbitMQ.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	templateManager, err := template.NewManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create template manager: %w", err)
	}

	emailService := email_center.NewEmailService(cfg, templateManager)

	return &EmailConsumer{
		cfg:          cfg,
		conn:         conn,
		emailService: emailService,
	}, nil
}

func (c *EmailConsumer) Start(ctx context.Context) error {
	ch, err := c.conn.Channel()
	if err != nil {
		return fmt.Errorf("failed to open a channel: %w", err)
	}

	log.Println("email_queue", c.cfg.RabbitMQ.EmailQueue)

	_, err = ch.QueueDeclare(c.cfg.RabbitMQ.EmailQueue, true, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	msgs, err := ch.Consume(
		c.cfg.RabbitMQ.EmailQueue,
		"",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to declare a queue: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d := <-msgs:
			var msg email_center.Message
			if err := json.Unmarshal(d.Body, &msg); err != nil {
				log.Printf("worker: bad payload: %v", err)
				continue
			}
			if err := c.emailService.Send(msg); err != nil {
				log.Printf("worker: email_center processing error: %v", err)
			}
		}
	}
}

func (c *EmailConsumer) Close() error {
	return c.conn.Close()
}
