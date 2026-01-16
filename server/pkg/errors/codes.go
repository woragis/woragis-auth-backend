package errors

// Error code format: SERVICE_CATEGORY_NUMBER
// Each code should be used in exactly one place for easy tracking

const (
	// AUTH - Authentication errors (1000-1099)
	AUTH_JWT_INVALID_SIGNATURE    = "AUTH_1001"
	AUTH_JWT_EXPIRED              = "AUTH_1002"
	AUTH_JWT_MISSING_CLAIMS       = "AUTH_1003"
	AUTH_JWT_MALFORMED            = "AUTH_1004"
	AUTH_JWT_GENERATION_FAILED    = "AUTH_1005"
	AUTH_INVALID_CREDENTIALS      = "AUTH_1010"
	AUTH_USER_NOT_FOUND           = "AUTH_1011"
	AUTH_PASSWORD_MISMATCH        = "AUTH_1012"
	AUTH_EMAIL_ALREADY_EXISTS     = "AUTH_1013"
	AUTH_WEAK_PASSWORD            = "AUTH_1014"
	AUTH_TOKEN_MISSING            = "AUTH_1020"
	AUTH_TOKEN_INVALID_FORMAT     = "AUTH_1021"
	AUTH_UNAUTHORIZED             = "AUTH_1022"

	// CSRF - CSRF token errors (2000-2099)
	CSRF_TOKEN_EXPIRED            = "AUTH_2001"
	CSRF_TOKEN_INVALID            = "AUTH_2002"
	CSRF_TOKEN_MISSING            = "AUTH_2003"
	CSRF_TOKEN_GENERATION_FAILED  = "AUTH_2004"
	CSRF_TOKEN_MISMATCH           = "AUTH_2005"

	// DB - Database errors (3000-3099)
	DB_CONNECTION_FAILED          = "AUTH_3001"
	DB_QUERY_FAILED               = "AUTH_3002"
	DB_TRANSACTION_FAILED         = "AUTH_3003"
	DB_RECORD_NOT_FOUND           = "AUTH_3004"
	DB_DUPLICATE_ENTRY            = "AUTH_3005"
	DB_CONSTRAINT_VIOLATION       = "AUTH_3006"
	DB_CREATE_FAILED              = "AUTH_3007"
	DB_UPDATE_FAILED              = "AUTH_3008"
	DB_DELETE_FAILED              = "AUTH_3009"

	// VALIDATION - Input validation errors (4000-4099)
	VALIDATION_INVALID_EMAIL      = "AUTH_4001"
	VALIDATION_INVALID_INPUT      = "AUTH_4002"
	VALIDATION_MISSING_FIELD      = "AUTH_4003"
	VALIDATION_FIELD_TOO_LONG     = "AUTH_4004"
	VALIDATION_FIELD_TOO_SHORT    = "AUTH_4005"

	// REDIS - Redis/Cache errors (5000-5099)
	REDIS_CONNECTION_FAILED       = "AUTH_5001"
	REDIS_GET_FAILED              = "AUTH_5002"
	REDIS_SET_FAILED              = "AUTH_5003"
	REDIS_DELETE_FAILED           = "AUTH_5004"

	// CRYPTO - Cryptography errors (6000-6099)
	CRYPTO_HASH_FAILED            = "AUTH_6001"
	CRYPTO_ENCRYPT_FAILED         = "AUTH_6002"
	CRYPTO_DECRYPT_FAILED         = "AUTH_6003"
	CRYPTO_RANDOM_GEN_FAILED      = "AUTH_6004"
	CRYPTO_TOKEN_GENERATION_FAILED = "AUTH_6005"

	// SERVER - Server/System errors (9000-9099)
	SERVER_INTERNAL_ERROR         = "AUTH_9001"
	SERVER_SERVICE_UNAVAILABLE    = "AUTH_9002"
	SERVER_TIMEOUT                = "AUTH_9003"
	SERVER_CONTEXT_CANCELLED      = "AUTH_9004"
)

// Error messages - human-readable descriptions
var errorMessages = map[string]string{
	// Authentication
	AUTH_JWT_INVALID_SIGNATURE:   "JWT token signature is invalid",
	AUTH_JWT_EXPIRED:             "JWT token has expired",
	AUTH_JWT_MISSING_CLAIMS:      "JWT token is missing required claims",
	AUTH_JWT_MALFORMED:           "JWT token is malformed",
	AUTH_JWT_GENERATION_FAILED:   "Failed to generate JWT token",
	AUTH_INVALID_CREDENTIALS:     "Invalid email or password",
	AUTH_USER_NOT_FOUND:          "User account not found",
	AUTH_PASSWORD_MISMATCH:       "Password does not match",
	AUTH_EMAIL_ALREADY_EXISTS:    "Email address is already registered",
	AUTH_WEAK_PASSWORD:           "Password does not meet security requirements",
	AUTH_TOKEN_MISSING:           "Authentication token is missing",
	AUTH_TOKEN_INVALID_FORMAT:    "Authentication token has invalid format",
	AUTH_UNAUTHORIZED:            "Unauthorized access",

	// CSRF
	CSRF_TOKEN_EXPIRED:           "CSRF token has expired",
	CSRF_TOKEN_INVALID:           "CSRF token validation failed",
	CSRF_TOKEN_MISSING:           "CSRF token is missing from request",
	CSRF_TOKEN_GENERATION_FAILED: "Failed to generate CSRF token",
	CSRF_TOKEN_MISMATCH:          "CSRF token does not match stored value",

	// Database
	DB_CONNECTION_FAILED:         "Failed to connect to database",
	DB_QUERY_FAILED:              "Database query execution failed",
	DB_TRANSACTION_FAILED:        "Database transaction failed",
	DB_RECORD_NOT_FOUND:          "Requested record not found",
	DB_DUPLICATE_ENTRY:           "Record already exists",
	DB_CONSTRAINT_VIOLATION:      "Database constraint violation",
	DB_CREATE_FAILED:             "Failed to create record in database",
	DB_UPDATE_FAILED:             "Failed to update record in database",
	DB_DELETE_FAILED:             "Failed to delete record from database",

	// Validation
	VALIDATION_INVALID_EMAIL:     "Email address format is invalid",
	VALIDATION_INVALID_INPUT:     "Input validation failed",
	VALIDATION_MISSING_FIELD:     "Required field is missing",
	VALIDATION_FIELD_TOO_LONG:    "Field value exceeds maximum length",
	VALIDATION_FIELD_TOO_SHORT:   "Field value is below minimum length",

	// Redis
	REDIS_CONNECTION_FAILED:      "Failed to connect to Redis",
	REDIS_GET_FAILED:             "Failed to retrieve data from cache",
	REDIS_SET_FAILED:             "Failed to store data in cache",
	REDIS_DELETE_FAILED:          "Failed to delete data from cache",

	// Crypto
	CRYPTO_HASH_FAILED:           "Failed to hash data",
	CRYPTO_ENCRYPT_FAILED:        "Failed to encrypt data",
	CRYPTO_DECRYPT_FAILED:        "Failed to decrypt data",
	CRYPTO_RANDOM_GEN_FAILED:     "Failed to generate random data",
	CRYPTO_TOKEN_GENERATION_FAILED: "Failed to generate token",

	// Server
	SERVER_INTERNAL_ERROR:        "Internal server error occurred",
	SERVER_SERVICE_UNAVAILABLE:   "Service is temporarily unavailable",
	SERVER_TIMEOUT:               "Request timeout",
	SERVER_CONTEXT_CANCELLED:     "Request was cancelled",
}

// GetMessage returns the human-readable message for an error code
func GetMessage(code string) string {
	if msg, ok := errorMessages[code]; ok {
		return msg
	}
	return "Unknown error occurred"
}
