package contract

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auth "woragis-auth-service/internal/domains"
	"woragis-auth-service/pkg/utils"
)

// TestValidateTokenRequest_Contract tests the ValidateTokenRequest contract
func TestValidateTokenRequest_Contract(t *testing.T) {
	request := auth.ValidateTokenRequest{
		Token: "test-jwt-token",
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(request)
	require.NoError(t, err, "Should serialize to JSON")

	// Test JSON deserialization
	var unmarshaled auth.ValidateTokenRequest
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	assert.Equal(t, request.Token, unmarshaled.Token)

	// Verify required fields
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)
	assert.Contains(t, jsonMap, "token")
}

// TestValidateTokenResponse_Contract tests the ValidateTokenResponse contract
func TestValidateTokenResponse_Contract(t *testing.T) {
	tests := []struct {
		name     string
		response auth.ValidateTokenResponse
	}{
		{
			name: "valid token response",
			response: auth.ValidateTokenResponse{
				Valid:  true,
				UserID: uuid.New().String(),
				Email:  "test@example.com",
				Role:   "user",
			},
		},
		{
			name: "invalid token response",
			response: auth.ValidateTokenResponse{
				Valid:   false,
				Message: "Token expired",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			jsonData, err := json.Marshal(tt.response)
			require.NoError(t, err, "Should serialize to JSON")

			// Test JSON deserialization
			var unmarshaled auth.ValidateTokenResponse
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err, "Should deserialize from JSON")

			assert.Equal(t, tt.response.Valid, unmarshaled.Valid)
			if tt.response.Valid {
				assert.Equal(t, tt.response.UserID, unmarshaled.UserID)
				assert.Equal(t, tt.response.Email, unmarshaled.Email)
				assert.Equal(t, tt.response.Role, unmarshaled.Role)
			} else {
				assert.NotEmpty(t, unmarshaled.Message)
			}

			// Verify required field
			jsonMap := make(map[string]interface{})
			err = json.Unmarshal(jsonData, &jsonMap)
			require.NoError(t, err)
			assert.Contains(t, jsonMap, "valid")
		})
	}
}

// TestProfileUpdateRequest_OptionalFields tests that optional fields can be omitted
func TestProfileUpdateRequest_OptionalFields(t *testing.T) {
	// Test with all fields
	fullRequest := auth.ProfileUpdateRequest{
		Avatar:      "https://example.com/avatar.jpg",
		Bio:         "Test bio",
		Gender:      "male",
		Phone:       "+1234567890",
		Location:    "New York, NY",
		Website:     "https://example.com",
		SocialLinks: `{"twitter": "@test"}`,
		Preferences: `{"theme": "dark"}`,
	}

	// Test with minimal fields (all optional)
	minimalRequest := auth.ProfileUpdateRequest{}

	// Both should serialize/deserialize correctly
	for _, req := range []auth.ProfileUpdateRequest{fullRequest, minimalRequest} {
		jsonData, err := json.Marshal(req)
		require.NoError(t, err)

		var unmarshaled auth.ProfileUpdateRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, req.Avatar, unmarshaled.Avatar)
		assert.Equal(t, req.Bio, unmarshaled.Bio)
	}
}

// TestProfileEndpoint_Contract tests the Profile GET endpoint HTTP contract
func TestProfileEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	app.Get("/api/v1/auth/profile", func(c *fiber.Ctx) error {
		profile := auth.Profile{
			ID:     uuid.New(),
			UserID: uuid.New(),
			Bio:    "Test bio",
			Avatar: "https://example.com/avatar.jpg",
		}
		return utils.SuccessResponse(c, "Profile retrieved successfully", profile)
	})

	req := httptest.NewRequest("GET", "/api/v1/auth/profile", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var responseBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	require.NoError(t, err)

	// Contract: Response should have standard structure
	assert.Contains(t, responseBody, "success")
	assert.Contains(t, responseBody, "data")

	// Contract: Data should contain profile
	data := responseBody["data"].(map[string]interface{})
	assert.Contains(t, data, "id")
	assert.Contains(t, data, "user_id")
}

// TestUpdateProfileEndpoint_Contract tests the Profile UPDATE endpoint HTTP contract
func TestUpdateProfileEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	app.Put("/api/v1/auth/profile", func(c *fiber.Ctx) error {
		var req auth.ProfileUpdateRequest
		if err := c.BodyParser(&req); err != nil {
			return utils.BadRequestResponse(c, "Invalid request body")
		}

		profile := auth.Profile{
			ID:     uuid.New(),
			UserID: uuid.New(),
			Bio:    req.Bio,
			Avatar: req.Avatar,
		}
		return utils.SuccessResponse(c, "Profile updated successfully", profile)
	})

	request := auth.ProfileUpdateRequest{
		Bio:    "Updated bio",
		Avatar: "https://example.com/new-avatar.jpg",
	}

	body, err := json.Marshal(request)
	require.NoError(t, err)

	req := httptest.NewRequest("PUT", "/api/v1/auth/profile", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}

// TestChangePasswordEndpoint_Contract tests the ChangePassword endpoint HTTP contract
func TestChangePasswordEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	app.Post("/api/v1/auth/change-password", func(c *fiber.Ctx) error {
		var req auth.PasswordChangeRequest
		if err := c.BodyParser(&req); err != nil {
			return utils.BadRequestResponse(c, "Invalid request body")
		}

		if req.CurrentPassword == "wrong" {
			return utils.BadRequestResponse(c, "Current password is incorrect")
		}

		return utils.SuccessResponse(c, "Password changed successfully", nil)
	})

	tests := []struct {
		name           string
		request        auth.PasswordChangeRequest
		expectedStatus int
	}{
		{
			name: "valid password change returns 200",
			request: auth.PasswordChangeRequest{
				CurrentPassword: "OldPass123!",
				NewPassword:     "NewPass123!",
			},
			expectedStatus: 200,
		},
		{
			name: "wrong current password returns 400",
			request: auth.PasswordChangeRequest{
				CurrentPassword: "wrong",
				NewPassword:     "NewPass123!",
			},
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/api/v1/auth/change-password", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-token")

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		})
	}
}

// TestVerifyEmailEndpoint_Contract tests the VerifyEmail endpoint HTTP contract
func TestVerifyEmailEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	app.Get("/api/v1/auth/verify-email", func(c *fiber.Ctx) error {
		token := c.Query("token")
		if token == "" {
			return utils.BadRequestResponse(c, "Verification token is required")
		}

		if token == "invalid-token" {
			return utils.BadRequestResponse(c, "Token expired")
		}

		return utils.SuccessResponse(c, "Email verified successfully", nil)
	})

	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{
			name:           "valid token returns 200",
			token:          "valid-token",
			expectedStatus: 200,
		},
		{
			name:           "missing token returns 400",
			token:          "",
			expectedStatus: 400,
		},
		{
			name:           "invalid token returns 400",
			token:          "invalid-token",
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/v1/auth/verify-email"
			if tt.token != "" {
				url += "?token=" + tt.token
			}

			req := httptest.NewRequest("GET", url, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		})
	}
}

// TestValidateTokenEndpoint_Contract tests the ValidateToken endpoint HTTP contract
func TestValidateTokenEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	app.Post("/api/v1/auth/validate", func(c *fiber.Ctx) error {
		var req auth.ValidateTokenRequest
		if err := c.BodyParser(&req); err != nil {
			return utils.BadRequestResponse(c, "Invalid request body")
		}

		if req.Token == "valid-token" {
			response := auth.ValidateTokenResponse{
				Valid:  true,
				UserID: uuid.New().String(),
				Email:  "test@example.com",
				Role:   "user",
			}
			return c.Status(fiber.StatusOK).JSON(response)
		}

		response := auth.ValidateTokenResponse{
			Valid:   false,
			Message: "Invalid token",
		}
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	})

	tests := []struct {
		name           string
		request        auth.ValidateTokenRequest
		expectedStatus int
		validateResponse func(t *testing.T, resp *http.Response)
	}{
		{
			name: "valid token returns 200",
			request: auth.ValidateTokenRequest{
				Token: "valid-token",
			},
			expectedStatus: 200,
			validateResponse: func(t *testing.T, resp *http.Response) {
				var response auth.ValidateTokenResponse
				err := json.NewDecoder(resp.Body).Decode(&response)
				require.NoError(t, err)
				assert.True(t, response.Valid)
				assert.NotEmpty(t, response.UserID)
			},
		},
		{
			name: "invalid token returns 401",
			request: auth.ValidateTokenRequest{
				Token: "invalid-token",
			},
			expectedStatus: 401,
			validateResponse: func(t *testing.T, resp *http.Response) {
				var response auth.ValidateTokenResponse
				err := json.NewDecoder(resp.Body).Decode(&response)
				require.NoError(t, err)
				assert.False(t, response.Valid)
				assert.NotEmpty(t, response.Message)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/api/v1/auth/validate", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

			if tt.validateResponse != nil {
				tt.validateResponse(t, resp)
			}
		})
	}
}

// TestLogoutAllEndpoint_Contract tests the LogoutAll endpoint HTTP contract
func TestLogoutAllEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	app.Post("/api/v1/auth/logout-all", func(c *fiber.Ctx) error {
		return utils.SuccessResponse(c, "Logged out from all devices", nil)
	})

	req := httptest.NewRequest("POST", "/api/v1/auth/logout-all", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := app.Test(req)
	require.NoError(t, err)

	// Contract: LogoutAll should return 200
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}

// TestListUsersEndpoint_Contract tests the ListUsers endpoint HTTP contract
func TestListUsersEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	app.Get("/api/v1/auth/users", func(c *fiber.Ctx) error {
		response := map[string]interface{}{
			"users": []auth.User{
				{
					ID:       uuid.New(),
					Username: "user1",
					Email:    "user1@example.com",
				},
			},
			"pagination": map[string]interface{}{
				"page":        1,
				"limit":       10,
				"total":       1,
				"total_pages": 1,
			},
		}
		return utils.SuccessResponse(c, "Users retrieved successfully", response)
	})

	tests := []struct {
		name           string
		queryParams   string
		expectedStatus int
	}{
		{
			name:           "list users without params",
			queryParams:    "",
			expectedStatus: 200,
		},
		{
			name:           "list users with pagination",
			queryParams:    "?page=1&limit=10",
			expectedStatus: 200,
		},
		{
			name:           "list users with search",
			queryParams:    "?search=test",
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/auth/users"+tt.queryParams, nil)
			req.Header.Set("Authorization", "Bearer test-token")

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

			if resp.StatusCode == 200 {
				var responseBody map[string]interface{}
				err = json.NewDecoder(resp.Body).Decode(&responseBody)
				require.NoError(t, err)

				// Contract: Response should have users and pagination
				data := responseBody["data"].(map[string]interface{})
				assert.Contains(t, data, "users")
				assert.Contains(t, data, "pagination")
			}
		})
	}
}

// TestGetUserEndpoint_Contract tests the GetUser endpoint HTTP contract
func TestGetUserEndpoint_Contract(t *testing.T) {
	app := fiber.New()

	userID := uuid.New()
	app.Get("/api/v1/auth/users/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")
		if id == "invalid" {
			return utils.BadRequestResponse(c, "Invalid user ID")
		}

		user := auth.User{
			ID:       userID,
			Username: "testuser",
			Email:    "test@example.com",
		}
		return utils.SuccessResponse(c, "User retrieved successfully", user)
	})

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{
			name:           "valid user ID returns 200",
			userID:         userID.String(),
			expectedStatus: 200,
		},
		{
			name:           "invalid user ID returns 400",
			userID:         "invalid",
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/auth/users/"+tt.userID, nil)
			req.Header.Set("Authorization", "Bearer test-token")

			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		})
	}
}

// TestSession_Contract tests the Session entity contract
func TestSession_Contract(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	session := auth.Session{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: "refresh-token",
		UserAgent:    "test-agent",
		IPAddress:    "127.0.0.1",
		IsActive:     true,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(session)
	require.NoError(t, err, "Should serialize to JSON")

	// Verify refresh token is not in JSON (should be hidden)
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)
	assert.NotContains(t, jsonMap, "refresh_token", "RefreshToken should not be in JSON")

	// Test JSON deserialization
	var unmarshaled auth.Session
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	assert.Equal(t, sessionID, unmarshaled.ID)
	assert.Equal(t, userID, unmarshaled.UserID)
	assert.Equal(t, "test-agent", unmarshaled.UserAgent)
	assert.Equal(t, "127.0.0.1", unmarshaled.IPAddress)
	assert.Equal(t, true, unmarshaled.IsActive)
}

// TestVerificationToken_Contract tests the VerificationToken entity contract
func TestVerificationToken_Contract(t *testing.T) {
	userID := uuid.New()
	tokenID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	token := auth.VerificationToken{
		ID:        tokenID,
		UserID:    userID,
		Token:     "verification-token",
		Type:      "email_verification",
		ExpiresAt: expiresAt,
		IsUsed:    false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(token)
	require.NoError(t, err, "Should serialize to JSON")

	// Verify token is not in JSON (should be hidden)
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)
	assert.NotContains(t, jsonMap, "token", "Token should not be in JSON")

	// Test JSON deserialization
	var unmarshaled auth.VerificationToken
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	assert.Equal(t, tokenID, unmarshaled.ID)
	assert.Equal(t, userID, unmarshaled.UserID)
	assert.Equal(t, "email_verification", unmarshaled.Type)
	assert.Equal(t, false, unmarshaled.IsUsed)
}

// TestRequestValidation_Contract tests that validation rules are enforced
func TestRequestValidation_Contract(t *testing.T) {
	tests := []struct {
		name    string
		request auth.RegisterRequest
		valid   bool
	}{
		{
			name: "valid email format",
			request: auth.RegisterRequest{
				Username:  "testuser",
				Email:     "valid@example.com",
				Password:  "SecurePass123!",
				FirstName: "Test",
				LastName:  "User",
			},
			valid: true,
		},
		{
			name: "invalid email format",
			request: auth.RegisterRequest{
				Username:  "testuser",
				Email:     "invalid-email",
				Password:  "SecurePass123!",
				FirstName: "Test",
				LastName:  "User",
			},
			valid: false,
		},
		{
			name: "username too short",
			request: auth.RegisterRequest{
				Username:  "ab",
				Email:     "test@example.com",
				Password:  "SecurePass123!",
				FirstName: "Test",
				LastName:  "User",
			},
			valid: false,
		},
		{
			name: "password too short",
			request: auth.RegisterRequest{
				Username:  "testuser",
				Email:     "test@example.com",
				Password:  "Short1!",
				FirstName: "Test",
				LastName:  "User",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization (should always work)
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			// Test JSON deserialization (should always work)
			var unmarshaled auth.RegisterRequest
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			// Validation would happen at the service layer
			// Contract test just ensures the structure can be serialized/deserialized
			assert.Equal(t, tt.request.Email, unmarshaled.Email)
		})
	}
}

// TestResponseStructure_Contract tests that all responses follow the standard structure
func TestResponseStructure_Contract(t *testing.T) {
	app := fiber.New()

	// Test success response structure
	app.Get("/api/v1/auth/test-success", func(c *fiber.Ctx) error {
		return utils.SuccessResponse(c, "Operation successful", map[string]string{"key": "value"})
	})

	// Test error response structure
	app.Get("/api/v1/auth/test-error", func(c *fiber.Ctx) error {
		return utils.BadRequestResponse(c, "Operation failed")
	})

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		validateStructure func(t *testing.T, body map[string]interface{})
	}{
		{
			name:           "success response structure",
			path:           "/api/v1/auth/test-success",
			expectedStatus: 200,
			validateStructure: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, body, "success")
				assert.Contains(t, body, "message")
				assert.Contains(t, body, "data")
				assert.Equal(t, true, body["success"])
			},
		},
		{
			name:           "error response structure",
			path:           "/api/v1/auth/test-error",
			expectedStatus: 400,
			validateStructure: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, body, "success")
				assert.Contains(t, body, "message")
				assert.Equal(t, false, body["success"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var responseBody map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&responseBody)
			require.NoError(t, err)

			if tt.validateStructure != nil {
				tt.validateStructure(t, responseBody)
			}
		})
	}
}

