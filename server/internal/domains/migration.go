package auth

import (
	"gorm.io/gorm"
)

// MigrateAuthTables runs database migrations for auth domain
func MigrateAuthTables(db *gorm.DB) error {
	// Enable UUID extension if not already enabled
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return err
	}

	// Enable gen_random_uuid function if not already available
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"").Error; err != nil {
		return err
	}

	// Migrate auth tables
	if err := db.AutoMigrate(
		&User{},
		&Profile{},
		&Session{},
		&VerificationToken{},
	); err != nil {
		return err
	}

	// Create indexes for better performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
		"CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)",
		"CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)",
		"CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_verification_tokens_user_id ON verification_tokens(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_verification_tokens_token ON verification_tokens(token)",
		"CREATE INDEX IF NOT EXISTS idx_verification_tokens_type ON verification_tokens(type)",
		"CREATE INDEX IF NOT EXISTS idx_verification_tokens_expires_at ON verification_tokens(expires_at)",
	}

	for _, index := range indexes {
		if err := db.Exec(index).Error; err != nil {
			return err
		}
	}

	return nil
}
