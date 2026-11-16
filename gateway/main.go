// Sentinel SAST API gateway.
//
// Receives GitHub push webhooks, records a scan, fetches the changed source
// files and queues them for the analysis worker; consumes the worker's results
// and stores them; and serves scans and findings to the frontend.
//
//	webhook -> gateway -> scan_jobs -> worker -> scan_results -> gateway -> Postgres
package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2/middleware/logger"
)

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// rabbitURL builds the broker URL from the same variables the worker reads, so
// one .env configures both. RABBITMQ_URL overrides them when set.
func rabbitURL() string {
	if value := os.Getenv("RABBITMQ_URL"); value != "" {
		return value
	}
	return fmt.Sprintf("amqp://%s:%s@%s:%s/",
		url.QueryEscape(envOr("RABBITMQ_USER", "guest")),
		url.QueryEscape(envOr("RABBITMQ_PASSWORD", "guest")),
		envOr("RABBITMQ_HOST", "localhost"),
		envOr("RABBITMQ_PORT", "5672"))
}

// envDuration reads a Go duration ("30m", "90s"). A value that does not parse,
// or is not positive, is reported and replaced by the fallback rather than
// silently becoming zero.
func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		log.Printf("gateway: %s=%q is not a positive duration; using %s", key, value, fallback)
		return fallback
	}
	return parsed
}

// background runs the work that outlives a webhook response -- fetching the
// pushed files and queueing the job. It bounds how many run at once, so a
// burst of pushes cannot open an unbounded number of outbound connections,
// and it lets shutdown wait for the ones in flight.
type background struct {
	slots chan struct{}
	wg    sync.WaitGroup
}

func newBackground(concurrency int) *background {
	return &background{slots: make(chan struct{}, concurrency)}
}

func (b *background) Dispatch(work func()) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.slots <- struct{}{}
		defer func() { <-b.slots }()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("gateway: background task panicked: %v", r)
			}
		}()
		work()
	}()
}

// Wait blocks until every dispatched task has finished or the timeout passes,
// and reports whether they all finished.
func (b *background) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// reapStaleScans fails scans that have been pending longer than timeout, once
// a minute, until ctx is cancelled.
func reapStaleScans(ctx context.Context, store Store, timeout time.Duration) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	reason := fmt.Sprintf("no result arrived within %s", timeout)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			failed, err := store.FailStaleScans(ctx, timeout, reason)
			switch {
			case err != nil && ctx.Err() == nil:
				log.Printf("gateway: could not expire stale scans: %v", err)
			case failed > 0:
				log.Printf("gateway: marked %d scan(s) FAILED after %s without a result", failed, timeout)
			}
		}
	}
}

func main() {
	addr := envOr("GATEWAY_ADDR", ":3001")
	databaseURL := envOr("DATABASE_URL", "postgres://sentinel:password@localhost:5432/sentinel_db")
	scanQueue := envOr("SCAN_QUEUE", "scan_jobs")
	resultsQueue := envOr("RESULTS_QUEUE", "scan_results")
	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	apiToken := os.Getenv("GATEWAY_API_TOKEN")
	scanTimeout := envDuration("SCAN_TIMEOUT", 30*time.Minute)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	store, err := NewPostgresStore(startup, databaseURL)
	cancel()
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	defer store.Close()

	broker := NewBroker(rabbitURL())
	defer broker.Close()

	if secret == "" {
		log.Print("gateway: GITHUB_WEBHOOK_SECRET is not set; every webhook will be refused")
	}

	// The consumer reconnects on its own, so a broker that is down at startup
	// delays results rather than stopping the gateway from serving reads.
	go broker.ConsumeResults(ctx, resultsQueue, store)
	go reapStaleScans(ctx, store, scanTimeout)

	if apiToken == "" {
		log.Print("gateway: GATEWAY_API_TOKEN is not set; the read API is unauthenticated")
	}
	tasks := newBackground(4)

	app := NewApp(Deps{
		Store:     store,
		Publisher: broker,
		Fetcher: NewRawFetcher(
			envOr("GITHUB_RAW_BASE_URL", "https://raw.githubusercontent.com"),
			os.Getenv("GITHUB_TOKEN")),
		Secret:    secret,
		ScanQueue: scanQueue,
		APIToken:  apiToken,
		Dispatch:  tasks.Dispatch,
	}, logger.New())

	go func() {
		<-ctx.Done()
		if err := app.ShutdownWithTimeout(10 * time.Second); err != nil {
			log.Printf("gateway: shutdown: %v", err)
		}
	}()

	log.Printf("gateway: listening on %s (jobs -> %s, results <- %s)", addr, scanQueue, resultsQueue)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("gateway: %v", err)
	}

	// Listen has returned, so no new webhooks are arriving. Let the scans
	// already being fetched reach the queue; one cut off here would be left
	// PENDING until the stale-scan timeout.
	if !tasks.Wait(2 * time.Minute) {
		log.Print("gateway: shutdown: gave up waiting for in-flight scans")
	}
	log.Print("gateway: stopped")
}
