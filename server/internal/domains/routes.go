package auth

import (
	"woragis-auth-service/pkg/auth"
	"woragis-auth-service/pkg/middleware"

	"github.com/gofiber/fiber/v2"
)

// SetupRoutes sets up all auth routes
func SetupRoutes(api fiber.Router, handler *Handler, jwtManager *auth.JWTManager) {

	// Create auth group
	authGroup := api.Group("/auth")

	// Public routes (no authentication required)
	authGroup.Post("/register", handler.Register)
	authGroup.Post("/login", handler.Login)
	authGroup.Post("/refresh", handler.RefreshToken)
	authGroup.Post("/logout", handler.Logout)
	authGroup.Get("/verify-email", handler.VerifyEmail)
	authGroup.Post("/validate", handler.ValidateToken) // Token validation endpoint for other services

	// Protected routes (authentication required)
	authGroup.Use(middleware.JWTMiddleware(middleware.JWTConfig{
		JWTManager: jwtManager,
	}))

	// User profile routes
	authGroup.Get("/profile", handler.GetProfile)
	authGroup.Put("/profile", handler.UpdateProfile)
	authGroup.Post("/change-password", handler.ChangePassword)
	authGroup.Post("/logout-all", handler.LogoutAll)

	// Admin routes (admin role required)
	admin := authGroup.Group("/admin")
	admin.Use(middleware.RequireAdmin())

	admin.Get("/users/:id", handler.GetUser)
	admin.Get("/users", handler.ListUsers)
	admin.Post("/cleanup", handler.CleanupExpiredSessions)
}
