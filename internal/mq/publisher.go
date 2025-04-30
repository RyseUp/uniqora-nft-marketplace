package mq

import (
	"context"
	"encoding/json"
	"log"

	amqp "github.com/rabbitmq/amqp091-go"
)

type Publisher struct {
	ch    *amqp.Channel
	queue string
}

func NewPublisher(url, queue string) (*Publisher, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("failed to connect channel: %v", err)
		return nil, err
	}
	// durable queue, server‑named exchange (default)
	_, err = ch.QueueDeclare(queue, true, false, false, false, nil)
	if err != nil {
		log.Fatalf("failed to declare queue: %v", err)
		return nil, err
	}
	return &Publisher{ch: ch, queue: queue}, nil
}

func (p *Publisher) Publish(ctx context.Context, msg any) error {
	body, _ := json.Marshal(msg)
	return p.ch.PublishWithContext(ctx, "", p.queue, false, false,
		amqp.Publishing{ContentType: "application/json", Body: body})
}
