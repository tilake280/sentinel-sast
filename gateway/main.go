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

func main() {
	addr := envOr("GATEWAY_ADDR", ":3001")
	databaseURL := envOr("DATABASE_URL", "postgres://sentinel:password@localhost:5432/sentinel_db")
	scanQueue := envOr("SCAN_QUEUE", "scan_jobs")
	resultsQueue := envOr("RESULTS_QUEUE", "scan_results")
	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")

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

	app := NewApp(Deps{
		Store:     store,
		Publisher: broker,
		Fetcher: NewRawFetcher(
			envOr("GITHUB_RAW_BASE_URL", "https://raw.githubusercontent.com"),
			os.Getenv("GITHUB_TOKEN")),
		Secret:    secret,
		ScanQueue: scanQueue,
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
}
