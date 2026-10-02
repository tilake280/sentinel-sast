package main

import (
	"errors"
	"log"

	"github.com/gofiber/fiber/v2"
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
	})
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

	api.Post("/webhook", deps.handleWebhook)

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

// storeError logs the cause and returns a generic 500: a database error
// message is not something to hand to an API client.
func storeError(c *fiber.Ctx, err error) error {
	log.Printf("%s %s: %v", c.Method(), c.Path(), err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": "the scan store is unavailable",
	})
}
