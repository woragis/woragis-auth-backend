package contract

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auth "woragis-auth-service/internal/domains"
)

// TestRegisterRequest_Contract tests the RegisterRequest contract
func TestRegisterRequest_Contract(t *testing.T) {
	tests := []struct {
		name    string
		request auth.RegisterRequest
		valid   bool
	}{
		{
			name: "valid request with all fields",
			request: auth.RegisterRequest{
				Username:  "testuser",
				Email:     "test@example.com",
				Password:  "SecurePass123!",
				FirstName: "Test",
				LastName:  "User",
			},
			valid: true,
		},
		{
			name: "valid request with minimum length fields",
			request: auth.RegisterRequest{
				Username:  "abc",
				Email:     "a@b.co",
				Password:  "Pass123!",
				FirstName: "Ab",
				LastName:  "Cd",
			},
			valid: true,
		},
		{
			name: "valid request with maximum length fields",
			request: auth.RegisterRequest{
				Username:  "abcdefghijklmnopqrstuvwxyz1234",
				Email:     "verylongemailaddressthatisstillvalid@example.com",
				Password:  "VeryLongPassword123!",
				FirstName: "VeryLongFirstNameThatIsExactlyFiftyCharactersLong",
				LastName:  "VeryLongLastNameThatIsExactlyFiftyCharactersLong",
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err, "Should serialize to JSON")

			// Test JSON deserialization
			var unmarshaled auth.RegisterRequest
			err = json.Unmarshal(jsonData, &unmarshaled)
			if tt.valid {
				require.NoError(t, err, "Should deserialize from JSON")
				assert.Equal(t, tt.request.Username, unmarshaled.Username)
				assert.Equal(t, tt.request.Email, unmarshaled.Email)
				assert.Equal(t, tt.request.FirstName, unmarshaled.FirstName)
				assert.Equal(t, tt.request.LastName, unmarshaled.LastName)
				// Password should be serialized (not hidden)
				assert.Equal(t, tt.request.Password, unmarshaled.Password)
			}
		})
	}
}

// TestRegisterRequest_RequiredFields tests that required fields are enforced
func TestRegisterRequest_RequiredFields(t *testing.T) {
	// Test that all required fields are present in JSON structure
	request := auth.RegisterRequest{
		Username:  "testuser",
		Email:     "test@example.com",
		Password:  "SecurePass123!",
		FirstName: "Test",
		LastName:  "User",
	}

	jsonData, err := json.Marshal(request)
	require.NoError(t, err)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)

	// Verify all required fields are present
	assert.Contains(t, jsonMap, "username")
	assert.Contains(t, jsonMap, "email")
	assert.Contains(t, jsonMap, "password")
	assert.Contains(t, jsonMap, "first_name")
	assert.Contains(t, jsonMap, "last_name")
}

// TestLoginRequest_Contract tests the LoginRequest contract
func TestLoginRequest_Contract(t *testing.T) {
	tests := []struct {
		name    string
		request auth.LoginRequest
		valid   bool
	}{
		{
			name: "valid request with email",
			request: auth.LoginRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
			},
			valid: true,
		},
		{
			name: "valid request with username",
			request: auth.LoginRequest{
				Username: "testuser",
				Password: "SecurePass123!",
			},
			valid: true,
		},
		{
			name: "valid request with both email and username",
			request: auth.LoginRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "SecurePass123!",
			},
			valid: true,
		},
		{
			name: "missing password",
			request: auth.LoginRequest{
				Email: "test@example.com",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err, "Should serialize to JSON")

			// Test JSON deserialization
			var unmarshaled auth.LoginRequest
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err, "Should deserialize from JSON")

			if tt.valid {
				assert.Equal(t, tt.request.Password, unmarshaled.Password)
				if tt.request.Email != "" {
					assert.Equal(t, tt.request.Email, unmarshaled.Email)
				}
				if tt.request.Username != "" {
					assert.Equal(t, tt.request.Username, unmarshaled.Username)
				}
			}
		})
	}
}

// TestAuthResponse_Contract tests the AuthResponse contract
func TestAuthResponse_Contract(t *testing.T) {
	userID := uuid.New()
	response := auth.AuthResponse{
		User: &auth.User{
			ID:        userID,
			Username:  "testuser",
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
			Role:      "user",
			IsActive:  true,
			IsVerified: true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
		ExpiresAt:    1234567890,
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(response)
	require.NoError(t, err, "Should serialize to JSON")

	// Test JSON deserialization
	var unmarshaled auth.AuthResponse
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	// Validate required fields
	assert.NotNil(t, unmarshaled.User, "User should not be nil")
	assert.NotEmpty(t, unmarshaled.AccessToken, "AccessToken should not be empty")
	assert.NotEmpty(t, unmarshaled.RefreshToken, "RefreshToken should not be empty")
	assert.NotZero(t, unmarshaled.ExpiresAt, "ExpiresAt should not be zero")

	// Validate user fields
	assert.Equal(t, userID, unmarshaled.User.ID)
	assert.Equal(t, "testuser", unmarshaled.User.Username)
	assert.Equal(t, "test@example.com", unmarshaled.User.Email)
	assert.Equal(t, "Test", unmarshaled.User.FirstName)
	assert.Equal(t, "User", unmarshaled.User.LastName)
	assert.Equal(t, "user", unmarshaled.User.Role)

	// Verify password is not included in JSON (should be hidden)
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)
	userMap := jsonMap["user"].(map[string]interface{})
	assert.NotContains(t, userMap, "password", "Password should not be in JSON response")
}

// TestAuthResponse_RequiredFields tests that required fields are present
func TestAuthResponse_RequiredFields(t *testing.T) {
	response := auth.AuthResponse{
		User: &auth.User{
			ID: uuid.New(),
		},
		AccessToken:  "token",
		RefreshToken: "refresh",
		ExpiresAt:    1234567890,
	}

	jsonData, err := json.Marshal(response)
	require.NoError(t, err)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)

	// Verify all required fields are present
	assert.Contains(t, jsonMap, "user")
	assert.Contains(t, jsonMap, "access_token")
	assert.Contains(t, jsonMap, "refresh_token")
	assert.Contains(t, jsonMap, "expires_at")
}

// TestProfileUpdateRequest_Contract tests the ProfileUpdateRequest contract
func TestProfileUpdateRequest_Contract(t *testing.T) {
	dateOfBirth := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	request := auth.ProfileUpdateRequest{
		Avatar:      "https://example.com/avatar.jpg",
		Bio:         "Test bio",
		DateOfBirth: &dateOfBirth,
		Gender:      "male",
		Phone:       "+1234567890",
		Location:    "New York, NY",
		Website:     "https://example.com",
		SocialLinks: `{"twitter": "@test"}`,
		Preferences: `{"theme": "dark"}`,
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(request)
	require.NoError(t, err, "Should serialize to JSON")

	// Test JSON deserialization
	var unmarshaled auth.ProfileUpdateRequest
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	assert.Equal(t, request.Avatar, unmarshaled.Avatar)
	assert.Equal(t, request.Bio, unmarshaled.Bio)
	assert.Equal(t, request.Gender, unmarshaled.Gender)
	assert.Equal(t, request.Phone, unmarshaled.Phone)
	assert.Equal(t, request.Location, unmarshaled.Location)
	assert.Equal(t, request.Website, unmarshaled.Website)
	assert.Equal(t, request.SocialLinks, unmarshaled.SocialLinks)
	assert.Equal(t, request.Preferences, unmarshaled.Preferences)
	if request.DateOfBirth != nil {
		assert.NotNil(t, unmarshaled.DateOfBirth)
		assert.Equal(t, request.DateOfBirth.Unix(), unmarshaled.DateOfBirth.Unix())
	}
}

// TestPasswordChangeRequest_Contract tests the PasswordChangeRequest contract
func TestPasswordChangeRequest_Contract(t *testing.T) {
	request := auth.PasswordChangeRequest{
		CurrentPassword: "OldPass123!",
		NewPassword:     "NewPass123!",
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(request)
	require.NoError(t, err, "Should serialize to JSON")

	// Test JSON deserialization
	var unmarshaled auth.PasswordChangeRequest
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	assert.Equal(t, request.CurrentPassword, unmarshaled.CurrentPassword)
	assert.Equal(t, request.NewPassword, unmarshaled.NewPassword)

	// Verify required fields are present
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)
	assert.Contains(t, jsonMap, "current_password")
	assert.Contains(t, jsonMap, "new_password")
}

// TestUser_Contract tests the User entity contract
func TestUser_Contract(t *testing.T) {
	userID := uuid.New()
	now := time.Now()
	user := auth.User{
		ID:         userID,
		Username:   "testuser",
		Email:      "test@example.com",
		Password:   "hashed-password",
		FirstName:  "Test",
		LastName:   "User",
		Role:       "user",
		IsActive:   true,
		IsVerified: true,
		LastLogin:  &now,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(user)
	require.NoError(t, err, "Should serialize to JSON")

	// Verify password is not in JSON (should be hidden)
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)
	assert.NotContains(t, jsonMap, "password", "Password should not be in JSON")

	// Test JSON deserialization
	var unmarshaled auth.User
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	assert.Equal(t, userID, unmarshaled.ID)
	assert.Equal(t, "testuser", unmarshaled.Username)
	assert.Equal(t, "test@example.com", unmarshaled.Email)
	assert.Equal(t, "Test", unmarshaled.FirstName)
	assert.Equal(t, "User", unmarshaled.LastName)
	assert.Equal(t, "user", unmarshaled.Role)
	assert.Equal(t, true, unmarshaled.IsActive)
	assert.Equal(t, true, unmarshaled.IsVerified)
}

// TestProfile_Contract tests the Profile entity contract
func TestProfile_Contract(t *testing.T) {
	userID := uuid.New()
	profileID := uuid.New()
	dateOfBirth := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now()

	profile := auth.Profile{
		ID:          profileID,
		UserID:      userID,
		Avatar:      "https://example.com/avatar.jpg",
		Bio:         "Test bio",
		DateOfBirth: &dateOfBirth,
		Gender:      "male",
		Phone:       "+1234567890",
		Location:    "New York, NY",
		Website:     "https://example.com",
		SocialLinks: `{"twitter": "@test"}`,
		Preferences: `{"theme": "dark"}`,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(profile)
	require.NoError(t, err, "Should serialize to JSON")

	// Test JSON deserialization
	var unmarshaled auth.Profile
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "Should deserialize from JSON")

	assert.Equal(t, profileID, unmarshaled.ID)
	assert.Equal(t, userID, unmarshaled.UserID)
	assert.Equal(t, profile.Avatar, unmarshaled.Avatar)
	assert.Equal(t, profile.Bio, unmarshaled.Bio)
	assert.Equal(t, profile.Gender, unmarshaled.Gender)
	assert.Equal(t, profile.Phone, unmarshaled.Phone)
	assert.Equal(t, profile.Location, unmarshaled.Location)
	assert.Equal(t, profile.Website, unmarshaled.Website)
}

// TestBackwardCompatibility tests that contract changes don't break backward compatibility
func TestBackwardCompatibility(t *testing.T) {
	// Test that old response format can still be parsed
	oldResponseJSON := `{
		"user": {
			"id": "123e4567-e89b-12d3-a456-426614174000",
			"username": "testuser",
			"email": "test@example.com",
			"first_name": "Test",
			"last_name": "User",
			"role": "user",
			"is_active": true,
			"is_verified": true
		},
		"access_token": "token",
		"refresh_token": "refresh",
		"expires_at": 1234567890
	}`

	var response auth.AuthResponse
	err := json.Unmarshal([]byte(oldResponseJSON), &response)
	require.NoError(t, err, "Should parse old response format")

	assert.NotNil(t, response.User)
	assert.Equal(t, "testuser", response.User.Username)
	assert.Equal(t, "token", response.AccessToken)
	assert.Equal(t, "refresh", response.RefreshToken)
	assert.Equal(t, int64(1234567890), response.ExpiresAt)
}

