package routes

import (
	"api-auth/main/src/controllers"
	"api-auth/main/src/middleware"
	"github.com/gofiber/fiber/v2"
)

// PasswordRoutes func for describe group of private routes.
func PasswordRoutes(a *fiber.App) {
	// Create password protected routes group.
	route := a.Group("/v1/token/password")

	// Register a route for POST /v1/token/password/verify.
	route.Get("/verify", middleware.PasswordProtected(), controllers.TokenPasswordResetVerify)
}
