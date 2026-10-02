package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Publisher puts a message on a named queue.
type Publisher interface {
	Publish(ctx context.Context, queue string, body []byte) error
}

// Broker is the gateway's RabbitMQ connection: it publishes scan jobs and
// consumes scan results. It dials lazily and redials after a failure, so the
// gateway starts when the broker is down and recovers when it comes back.
type Broker struct {
	url string

	mu      sync.Mutex
	conn    *amqp.Connection
	channel *amqp.Channel
}

func NewBroker(url string) *Broker { return &Broker{url: url} }

// declare must match the worker's amqp_queue_declare (durable, not exclusive,
// not auto-delete). RabbitMQ rejects a redeclaration with different flags.
func declare(channel *amqp.Channel, queue string) error {
	_, err := channel.QueueDeclare(queue, true, false, false, false, nil)
	return err
}

// publishChannel returns the shared channel, dialling if there is none.
// Callers hold b.mu.
func (b *Broker) publishChannel() (*amqp.Channel, error) {
	if b.conn != nil && !b.conn.IsClosed() && b.channel != nil && !b.channel.IsClosed() {
		return b.channel, nil
	}
	b.closeLocked()

	conn, err := amqp.Dial(b.url)
	if err != nil {
		return nil, fmt.Errorf("dial rabbitmq: %w", err)
	}
	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open channel: %w", err)
	}
	// Confirms turn "the broker took the bytes off the socket" into "the
	// broker has the message". Without them a publish to a dying connection
	// can report success.
	if err := channel.Confirm(false); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enable confirms: %w", err)
	}
	b.conn, b.channel = conn, channel
	return channel, nil
}

func (b *Broker) closeLocked() {
	if b.channel != nil {
		b.channel.Close()
	}
	if b.conn != nil {
		b.conn.Close()
	}
	b.conn, b.channel = nil, nil
}

func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked()
}

func (b *Broker) Publish(ctx context.Context, queue string, body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// One retry on a fresh connection: the usual failure is a connection that
	// went stale while the gateway sat idle.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		channel, err := b.publishChannel()
		if err != nil {
			lastErr = err
			continue
		}
		if err := declare(channel, queue); err != nil {
			lastErr = fmt.Errorf("declare %s: %w", queue, err)
			b.closeLocked()
			continue
		}

		confirmation, err := channel.PublishWithDeferredConfirmWithContext(ctx, "", queue, false, false,
			amqp.Publishing{
				ContentType:  "application/json",
				DeliveryMode: amqp.Persistent,
				Timestamp:    time.Now(),
				Body:         body,
			})
		if err != nil {
			lastErr = fmt.Errorf("publish to %s: %w", queue, err)
			b.closeLocked()
			continue
		}

		acked, err := confirmation.WaitContext(ctx)
		if err != nil {
			lastErr = fmt.Errorf("await confirm from %s: %w", queue, err)
			b.closeLocked()
			continue
		}
		if !acked {
			lastErr = fmt.Errorf("broker refused the message for %s", queue)
			continue
		}
		return nil
	}
	return lastErr
}

// errPoisonResult marks a result that can never be stored: it is not valid
// JSON, or names no job. Redelivering it would loop forever, so it is dropped.
var errPoisonResult = errors.New("unusable result message")

// handleResult stores one worker result. Split from the consume loop so the
// decision it makes -- store, drop, or retry -- is testable without a broker.
func handleResult(ctx context.Context, store Store, body []byte) error {
	var result ScanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("%w: %v", errPoisonResult, err)
	}
	if result.JobID == "" {
		return fmt.Errorf("%w: no job_id", errPoisonResult)
	}
	return store.SaveResult(ctx, result)
}

// ConsumeResults reads the results queue until ctx is cancelled, reconnecting
// with backoff whenever the connection drops.
func (b *Broker) ConsumeResults(ctx context.Context, queue string, store Store) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := b.consumeOnce(ctx, queue, store)
		if ctx.Err() != nil {
			return
		}
		log.Printf("results consumer: %v; reconnecting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (b *Broker) consumeOnce(ctx context.Context, queue string, store Store) error {
	// A connection of its own: a consumer that shared the publishing channel
	// would be torn down by every publish error.
	conn, err := amqp.Dial(b.url)
	if err != nil {
		return fmt.Errorf("dial rabbitmq: %w", err)
	}
	defer conn.Close()

	channel, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("open channel: %w", err)
	}
	if err := declare(channel, queue); err != nil {
		return fmt.Errorf("declare %s: %w", queue, err)
	}
	if err := channel.Qos(10, 0, false); err != nil {
		return fmt.Errorf("set qos: %w", err)
	}

	// Manual acks: a result is only removed from the queue once it is in
	// Postgres.
	deliveries, err := channel.ConsumeWithContext(ctx, queue, "sentinel-gateway", false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("consume %s: %w", queue, err)
	}
	log.Printf("results consumer: listening on %s", queue)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case delivery, open := <-deliveries:
			if !open {
				return errors.New("delivery channel closed")
			}

			err := handleResult(ctx, store, delivery.Body)
			switch {
			case err == nil:
				delivery.Ack(false)
			case errors.Is(err, errPoisonResult):
				log.Printf("results consumer: dropping message: %v", err)
				delivery.Reject(false)
			default:
				// Most likely the database is unavailable. Put the result back
				// and pause, rather than spinning on the same message.
				log.Printf("results consumer: could not store result: %v", err)
				delivery.Nack(false, true)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
				}
			}
		}
	}
}
