package main

import (
	"log"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func main() {
	app := fiber.New(fiber.Config{
		AppName: "Sentinel SAST API Gateway",
	})

	app.Use(logger.New())

	api := app.Group("/api/v1")

	// Health Check
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "online",
			"message": "Sentinel API Gateway is running",
		})
	})

	// Webhook Ingestion Endpoint
	api.Post("/webhook", func(c *fiber.Ctx) error {
		// Mock receiving a push event
		payload := string(c.Body())
		log.Printf("Received Webhook Payload: %s", payload)
		
		// TODO: Validate signature, insert PENDING record to Postgres, push to RabbitMQ
		
		return c.Status(202).JSON(fiber.Map{
			"status": "accepted",
			"message": "Scan job queued",
		})
	})

	log.Fatal(app.Listen(":3001"))
}
