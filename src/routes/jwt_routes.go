package routes

import (
	"api-auth/main/src/controllers"
	"api-auth/main/src/middleware"

	"github.com/gofiber/fiber/v2"
)

// JwtRoutes func for describe group of private routes.
func JwtRoutes(a *fiber.App) {
	// Create protected routes group.
	route := a.Group("/v1")

	// Register a route for POST /v1/token.
	route.Get("/token", middleware.JWTProtected(), controllers.Token)
	route.Get("/token/verify", middleware.JWTProtected(), controllers.TokenVerify)
	route.Get("/token/refresh", middleware.JWTProtected(), controllers.CreateRefreshToken)
	route.Post("/token/email", middleware.JWTProtected(), controllers.TokenEmailVerification)
	route.Post("/token/app", middleware.JWTProtected(), controllers.UpdateUserIdentityApp)

	// Register a route for POST /v1/sign-out.
	route.Post("/sign-out", middleware.JWTProtected(), controllers.SignOut)

	// Register routes for the logged-in user.
	route.Get("/user", middleware.JWTProtected(), controllers.GetSignedInUser)
	route.Put("/user", middleware.JWTProtected(), controllers.UpdateSignedInUser)
	route.Put("/user/password", middleware.JWTProtected(), controllers.UpdateUserPassword)

	// Register routes for the user CRUD.
	route.Get("/users", middleware.JWTProtected(), controllers.GetUsers)
	route.Post("/users", middleware.JWTProtected(), controllers.CreateUser)
	route.Get("/users/lookup", middleware.JWTProtected(), controllers.GetUsersLookup)
	route.Get("/users/:id", middleware.JWTProtected(), controllers.GetUser)
	route.Put("/users/:id", middleware.JWTProtected(), controllers.UpdateUser)
	route.Delete("/users/:id", middleware.JWTProtected(), controllers.DeleteUser)
	route.Put("/users/:id/restore", middleware.JWTProtected(), controllers.RestoreUser)
}
