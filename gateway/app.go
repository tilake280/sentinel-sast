package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// Deps is everything the HTTP layer depends on. main wires the real
// implementations; the tests wire fakes. Both build the app with NewApp, so
// the routes under test are the routes that ship.
type Deps struct {
	Store     Store
	Publisher Publisher
	Fetcher   ContentFetcher

	Secret    string // GITHUB_WEBHOOK_SECRET
	ScanQueue string

	// APIToken, when set, is required as a bearer token on the read endpoints
	// (scans, stats). Empty leaves them open, which is only appropriate when
	// the gateway is reachable from nothing but the frontend.
	APIToken string

	// Dispatch runs work that continues after the webhook has been answered.
	// Nil means a goroutine. Tests run it inline so they can assert on the
	// outcome without sleeping.
	Dispatch func(func())
}

func (d Deps) dispatch(work func()) {
	if d.Dispatch != nil {
		d.Dispatch(work)
		return
	}
	go work()
}

// NewApp builds the gateway's routes.
func NewApp(deps Deps, middleware ...fiber.Handler) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName: "Sentinel SAST API Gateway",
		// A push payload lists every changed path; the default 4 MiB is ample,
		// stated here so the limit is a decision rather than an accident.
		BodyLimit: 4 << 20,
		// Without these a client that opens a connection and never finishes
		// its request holds it open indefinitely.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	})
	// A panic in one handler answers 500 instead of ending the process.
	app.Use(recover.New())
	for _, handler := range middleware {
		app.Use(handler)
	}

	api := app.Group("/api/v1")

	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "online",
			"message": "Sentinel API Gateway is running",
		})
	})

	// Liveness says the process is up; readiness says it can do its job. An
	// orchestrator restarts on the first and routes traffic on the second.
	api.Get("/ready", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.UserContext(), 3*time.Second)
		defer cancel()
		if err := deps.Store.Ping(ctx); err != nil {
			log.Printf("readiness: store: %v", err)
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "unavailable",
				"store":  "unreachable",
			})
		}
		return c.JSON(fiber.Map{"status": "ready", "store": "ok"})
	})

	api.Post("/webhook", deps.handleWebhook)

	// Everything registered below is the read API, and is what the token
	// guards. The webhook authenticates by signature instead.
	api.Use(deps.requireToken)

	api.Get("/scans", func(c *fiber.Ctx) error {
		limit := c.QueryInt("limit", 50)
		if limit < 1 || limit > 200 {
			limit = 50
		}
		scans, err := deps.Store.ListScans(c.UserContext(), limit)
		if err != nil {
			return storeError(c, err)
		}
		return c.JSON(fiber.Map{"scans": scans})
	})

	api.Get("/scans/:id", func(c *fiber.Ctx) error {
		scan, findings, err := deps.Store.GetScan(c.UserContext(), c.Params("id"))
		if errors.Is(err, ErrScanNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "scan not found"})
		}
		if err != nil {
			return storeError(c, err)
		}
		return c.JSON(fiber.Map{"scan": scan, "findings": findings})
	})

	api.Get("/stats", func(c *fiber.Ctx) error {
		stats, err := deps.Store.Stats(c.UserContext())
		if err != nil {
			return storeError(c, err)
		}
		return c.JSON(stats)
	})

	return app
}

// requireToken enforces APIToken on the routes registered after it.
func (d Deps) requireToken(c *fiber.Ctx) error {
	if d.APIToken == "" {
		return c.Next()
	}
	given, found := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	// Hash both sides so the comparison is constant-time regardless of length.
	want := sha256.Sum256([]byte(d.APIToken))
	got := sha256.Sum256([]byte(given))
	if !found || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		c.Set(fiber.HeaderWWWAuthenticate, "Bearer")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "missing or invalid bearer token",
		})
	}
	return c.Next()
}

// storeError logs the cause and returns a generic 500: a database error
// message is not something to hand to an API client.
func storeError(c *fiber.Ctx, err error) error {
	log.Printf("%s %s: %v", c.Method(), c.Path(), err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": "the scan store is unavailable",
	})
}
