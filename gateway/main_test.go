package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// Setup sets up the Fiber app for testing without starting a server
func Setup() *fiber.App {
	app := fiber.New()

	api := app.Group("/api/v1")

	// Health Check
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "online",
			"message": "Sentinel API Gateway is running",
		})
	})

	// Webhook Ingestion Endpoint
	api.Post("/webhook", func(c *fiber.Ctx) error {
		return c.Status(202).JSON(fiber.Map{
			"status":  "accepted",
			"message": "Scan job queued",
		})
	})

	return app
}

func TestHealthEndpoint(t *testing.T) {
	app := Setup()

	req, _ := http.NewRequest("GET", "/api/v1/health", nil)
	resp, err := app.Test(req, -1)

	if err != nil {
		t.Fatalf("Failed to test health endpoint: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %v", resp.StatusCode)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	expected := `{"message":"Sentinel API Gateway is running","status":"online"}`
	if string(body) != expected {
		t.Errorf("Expected body %v, got %v", expected, string(body))
	}
}

func TestWebhookEndpoint(t *testing.T) {
	app := Setup()

	payload := []byte(`{"repository": "sentinel-sast", "commit": "a1b2c3d4"}`)
	req, _ := http.NewRequest("POST", "/api/v1/webhook", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)

	if err != nil {
		t.Fatalf("Failed to test webhook endpoint: %v", err)
	}

	if resp.StatusCode != 202 {
		t.Errorf("Expected status code 202, got %v", resp.StatusCode)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	expected := `{"message":"Scan job queued","status":"accepted"}`
	if string(body) != expected {
		t.Errorf("Expected body %v, got %v", expected, string(body))
	}
}
