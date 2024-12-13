package routes

import (
	"api-auth/main/src/controllers"
	"api-auth/main/src/middleware"
	"github.com/gofiber/fiber/v2"
)

// EmailRoutes func for describe group of private routes.
func EmailRoutes(a *fiber.App) {
	// Create email protected routes group.
	route := a.Group("/v1/token/email")

	// Register a route for GET /v1/token/email/verify.
	route.Get("/verify", middleware.EmailProtected(), controllers.TokenEmailVerificationVerify)

	// Register a route for PUT /v1/token/email/verification.
	route.Put("/verification", middleware.EmailProtected(), controllers.UpdateUserEmailVerification)
}
