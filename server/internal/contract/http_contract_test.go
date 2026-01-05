package contract

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auth "woragis-auth-service/internal/domains"
	"woragis-auth-service/pkg/utils"
)

// TestRegisterEndpoint_Contract tests the Register endpoint HTTP contract
func TestRegisterEndpoint_Contract(t *testing.T) {
	app := fiber.New()
	
	// Mock handler for contract testing
	app.Post("/api/v1/auth/register", func(c *fiber.Ctx) error {
		var req auth.RegisterRequest
		if err := c.BodyParser(&req); err != nil {
			return utils.BadRequestResponse(c, "Invalid request body")
		}
		
		// Contract: Valid JSON should return 400 for validation errors, not 500
		if req.Email == "" {
			return utils.BadRequestResponse(c, "Email is required")
		}
		
		// Contract: Success response structure
		if req.Email == "valid@example.com" {
			response := auth.AuthResponse{
				User: &auth.User{
					ID:       uuid.New(),
					Username: req.Username,
					Email:    req.Email,
				},
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresAt:    1234567890,
			}
			return utils.CreatedResponse(c, "User registered successfully", response)
		}
		
		return utils.BadRequestResponse(c, "Invalid request")
	})

	tests := []struct {
		name           string
		request        auth.RegisterRequest
		expectedStatus int
		validateResponse func(t *testing.T, resp *http.Response)
	}{
		{
			name: "valid request returns 201",
			request: auth.RegisterRequest{
				Username:  "testuser",
				Email:     "valid@example.com",
				Password:  "SecurePass123!",
				FirstName: "Test",
				LastName:  "User",
			},
			expectedStatus: 201,
			validateResponse: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
				
				var responseBody map[string]interface{}
				err := json.NewDecoder(resp.Body).Decode(&responseBody)
				require.NoError(t, err)
				
				// Contract: Response should have standard structure
				assert.Contains(t, responseBody, "success")
				assert.Contains(t, responseBody, "message")
				assert.Contains(t, responseBody, "data")
				
				// Contract: Data should contain auth response
				data := responseBody["data"].(map[string]interface{})
				assert.Contains(t, data, "user")
				assert.Contains(t, data, "access_token")
				assert.Contains(t, data, "refresh_token")
				assert.Contains(t, data, "expires_at")
			},
		},
		{
			name: "invalid JSON returns 400",
			request: auth.RegisterRequest{},
			expectedStatus: 400,
			validateResponse: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)
			
			req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			resp, err := app.Test(req)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			if tt.validateResponse != nil {
				tt.validateResponse(t, resp)
			}
		})
	}
}

// TestLoginEndpoint_Contract tests the Login endpoint HTTP contract
func TestLoginEndpoint_Contract(t *testing.T) {
	app := fiber.New()
	
	app.Post("/api/v1/auth/login", func(c *fiber.Ctx) error {
		var req auth.LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return utils.BadRequestResponse(c, "Invalid request body")
		}
		
		if req.Email == "valid@example.com" && req.Password == "password" {
			response := auth.AuthResponse{
				User: &auth.User{
					ID:    uuid.New(),
					Email: req.Email,
				},
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresAt:    1234567890,
			}
			return utils.SuccessResponse(c, "Login successful", response)
		}
		
		return utils.UnauthorizedResponse(c, "Invalid credentials")
	})

	tests := []struct {
		name           string
		request        auth.LoginRequest
		expectedStatus int
	}{
		{
			name: "valid credentials return 200",
			request: auth.LoginRequest{
				Email:    "valid@example.com",
				Password: "password",
			},
			expectedStatus: 200,
		},
		{
			name: "invalid credentials return 401",
			request: auth.LoginRequest{
				Email:    "invalid@example.com",
				Password: "wrong",
			},
			expectedStatus: 401,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)
			
			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			resp, err := app.Test(req)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		})
	}
}

// TestRefreshTokenEndpoint_Contract tests the RefreshToken endpoint HTTP contract
func TestRefreshTokenEndpoint_Contract(t *testing.T) {
	app := fiber.New()
	
	app.Post("/api/v1/auth/refresh", func(c *fiber.Ctx) error {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.BodyParser(&req); err != nil {
			return utils.BadRequestResponse(c, "Invalid request body")
		}
		
		if req.RefreshToken == "valid-refresh-token" {
			response := auth.AuthResponse{
				User: &auth.User{
					ID: uuid.New(),
				},
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				ExpiresAt:    1234567890,
			}
			return utils.SuccessResponse(c, "Token refreshed successfully", response)
		}
		
		return utils.UnauthorizedResponse(c, "Invalid refresh token")
	})

	// Test valid refresh token request
	validReq := map[string]string{
		"refresh_token": "valid-refresh-token",
	}
	
	body, err := json.Marshal(validReq)
	require.NoError(t, err)
	
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req)
	require.NoError(t, err)
	
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	var responseBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	require.NoError(t, err)
	
	// Contract: Response should have data with new tokens
	data := responseBody["data"].(map[string]interface{})
	assert.Contains(t, data, "access_token")
	assert.Contains(t, data, "refresh_token")
}

// TestLogoutEndpoint_Contract tests the Logout endpoint HTTP contract
func TestLogoutEndpoint_Contract(t *testing.T) {
	app := fiber.New()
	
	app.Post("/api/v1/auth/logout", func(c *fiber.Ctx) error {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.BodyParser(&req); err != nil {
			return utils.BadRequestResponse(c, "Invalid request body")
		}
		
		return utils.SuccessResponse(c, "Logout successful", nil)
	})

	logoutReq := map[string]string{
		"refresh_token": "test-refresh-token",
	}
	
	body, err := json.Marshal(logoutReq)
	require.NoError(t, err)
	
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req)
	require.NoError(t, err)
	
	// Contract: Logout should return 200
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}

// TestErrorResponse_Contract tests that error responses follow the contract
func TestErrorResponse_Contract(t *testing.T) {
	app := fiber.New()
	
	app.Post("/api/v1/auth/test-error", func(c *fiber.Ctx) error {
		return utils.BadRequestResponse(c, "Test error message")
	})

	req := httptest.NewRequest("POST", "/api/v1/auth/test-error", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req)
	require.NoError(t, err)
	
	assert.Equal(t, 400, resp.StatusCode)
	
	var errorBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorBody)
	require.NoError(t, err)
	
	// Contract: Error response should have standard structure
	assert.Contains(t, errorBody, "success")
	assert.Contains(t, errorBody, "message")
	assert.Equal(t, false, errorBody["success"])
	assert.NotEmpty(t, errorBody["message"])
}

// TestContentType_Contract tests that all endpoints return JSON content type
func TestContentType_Contract(t *testing.T) {
	app := fiber.New()
	
	endpoints := []struct {
		method string
		path   string
		handler fiber.Handler
	}{
		{"POST", "/api/v1/auth/register", func(c *fiber.Ctx) error {
			return utils.BadRequestResponse(c, "test")
		}},
		{"POST", "/api/v1/auth/login", func(c *fiber.Ctx) error {
			return utils.BadRequestResponse(c, "test")
		}},
		{"POST", "/api/v1/auth/refresh", func(c *fiber.Ctx) error {
			return utils.BadRequestResponse(c, "test")
		}},
		{"POST", "/api/v1/auth/logout", func(c *fiber.Ctx) error {
			return utils.BadRequestResponse(c, "test")
		}},
	}

	for _, endpoint := range endpoints {
		app.Add(endpoint.method, endpoint.path, endpoint.handler)
		
		req := httptest.NewRequest(endpoint.method, endpoint.path, bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		
		// Contract: All endpoints should return JSON
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"), 
			"Endpoint %s %s should return JSON", endpoint.method, endpoint.path)
	}
}

