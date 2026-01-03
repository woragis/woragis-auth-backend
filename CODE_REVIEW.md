# Auth Service Code Review - Dead Code & Inconsistencies

## Summary

This document outlines dead code and inconsistencies found in the auth service after refactoring.

## 🗑️ Dead Code

### 1. Unused Repository Methods

These methods are defined in the `Repository` interface and implemented but **never called**:

- **`deleteUser(id uuid.UUID) error`** (repository.go:188)
  - Soft deletes a user
  - Not used anywhere in the codebase (only in test mocks)

- **`deleteProfile(userID uuid.UUID) error`** (repository.go:360)
  - Soft deletes a profile
  - Not used anywhere in the codebase (only in test mocks)

- **`getSessionsByUserID(userID uuid.UUID) ([]Session, error)`** (repository.go:424)
  - Retrieves all active sessions for a user
  - Not used anywhere in the codebase (only in test mocks)

- **`updateSession(session *Session) error`** (repository.go:449)
  - Updates a session
  - Not used in service layer (only in test mocks and benchmarks)

### 2. Unused Service Method

- **`createVerificationToken(userID uuid.UUID, tokenType string) (*VerificationToken, error)`** (service.go:448)
  - Defined in Service interface and implemented
  - **Never called** by any handler or service method
  - The verification token creation logic exists but is not invoked
  - **Note**: Email verification tokens might be intended to be created during registration, but this method is not being called

### 3. Unused Entity Methods

- **`GetFullName() string`** (entity.go:106)
  - Returns user's full name (FirstName + LastName)
  - Never used in handlers or services

- **`IsModerator() bool`** (entity.go:116)
  - Checks if user has moderator or admin role
  - Never used anywhere in the codebase

### 4. Unused Error

- **`ErrUserNotVerified`** (service.go:17)
  - Error defined but never returned or checked
  - Email verification exists but this error is not used

### 5. Unused Import

- **`crypto` package** (service.go:9)
  - Only used in `createVerificationToken` method, which is dead code
  - Import: `"woragis-auth-service/pkg/crypto"`

## 🔄 Inconsistencies

### 1. Route Documentation Mismatch

The handler documentation (godoc `@Router` annotations) doesn't match the actual routes:

| Handler | Documented Route | Actual Route | Issue |
|---------|-----------------|--------------|-------|
| `GetUser` | `/auth/users/{id}` | `/auth/admin/users/:id` | Missing `/admin` prefix |
| `ListUsers` | `/auth/users` | `/auth/admin/users` | Missing `/admin` prefix |
| `CleanupExpiredSessions` | `/auth/cleanup` | `/auth/admin/cleanup` | Missing `/admin` prefix |

**Location**: handlers.go lines 431, 472, 522

**Impact**: API documentation is incorrect and could mislead developers

### 2. Redundant Admin Role Checks

Admin handlers have redundant role checks even though `RequireAdmin()` middleware is already applied:

**Affected Handlers:**
- `GetUser` (handlers.go:433-437)
- `ListUsers` (handlers.go:475-478)
- `CleanupExpiredSessions` (handlers.go:525-528)

**Current Code Pattern:**
```go
func (h *Handler) GetUser(c *fiber.Ctx) error {
    // Check if user is admin
    userRole, err := middleware.GetUserRoleFromFiberContext(c)
    if err != nil || userRole != "admin" {
        return utils.ForbiddenResponse(c, "Admin access required")
    }
    // ... rest of handler
}
```

**Issue**: The `RequireAdmin()` middleware (routes.go:37) already ensures only admins can access these routes. The handler-level check is redundant.

**Recommendation**: Remove the redundant checks from handlers since the middleware already enforces this.

## 📋 Recommendations

### High Priority

1. **Fix route documentation** - Update godoc `@Router` annotations to match actual routes
2. **Remove redundant admin checks** - Remove handler-level admin role checks since middleware handles it
3. **Remove unused `crypto` import** - Since `createVerificationToken` is dead code

### Medium Priority

4. **Decide on `createVerificationToken`** - Either:
   - Remove it if email verification tokens are not needed, OR
   - Integrate it into the registration flow if email verification is required
5. **Remove unused repository methods** - If user/profile deletion and session listing are not needed:
   - Remove `deleteUser`, `deleteProfile`, `getSessionsByUserID`, `updateSession`

### Low Priority

6. **Remove unused entity methods** - If `GetFullName()` and `IsModerator()` are not planned for use, remove them
7. **Remove unused error** - Remove `ErrUserNotVerified` if email verification check is not needed

## ✅ Code That is Correctly Used

The following are properly implemented and used:
- All handler methods are connected to routes
- All service methods (except `createVerificationToken`) are called by handlers
- All repository methods used by services are properly implemented
- All entity methods used in business logic are present

## Notes

- The service is well-structured with clear separation of concerns
- Test mocks include all repository methods, which is fine even if some are unused
- Some "dead code" might be intentional for future features (e.g., user deletion, profile deletion)
- Consider if email verification is a planned feature - if so, `createVerificationToken` should be integrated into registration flow

