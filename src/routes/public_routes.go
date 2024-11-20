package routes

import (
	"api-auth/main/src/controllers"
	"github.com/gofiber/fiber/v2"
)

// PublicRoutes func for describe group of public routes.
func PublicRoutes(a *fiber.App) {
	// Create public routes group.
	route := a.Group("/v1")
	// routeUsernamePassword := route.Group("/username-password")

	// Register a route for POST /v1/signup.
	route.Post("/signup", controllers.Signup)
}
