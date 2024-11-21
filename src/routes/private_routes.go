package routes

import (
	"api-auth/main/src/controllers"
	"github.com/ArnoldPMolenaar/api-utils/middleware"
	"github.com/gofiber/fiber/v2"
)

// PrivateRoutes func for describe group of private routes.
func PrivateRoutes(a *fiber.App) {
	// Create private routes group.
	route := a.Group("/v1", middleware.MachineProtected())
	// routeUsernamePassword := route.Group("/username-password")

	// Register a route for POST /v1/signup.
	route.Post("/signup", controllers.Signup)

	// Register a route for GET /v1/user/recipes.
	route.Get("/user/recipes", controllers.GetUserRecipesByUsername)
}
