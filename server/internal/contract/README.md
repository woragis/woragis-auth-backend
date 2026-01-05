# Contract Tests

This package contains contract tests for the Auth Service API. Contract tests verify that the service maintains its API contract (request/response formats, schemas, HTTP status codes) without requiring the full service stack to be running.

## What are Contract Tests?

Contract tests validate:
- **Request schemas**: JSON structure, required fields, data types
- **Response schemas**: JSON structure, required fields, data types
- **HTTP contracts**: Status codes, content types, response formats
- **Backward compatibility**: Changes don't break existing clients
- **Serialization/Deserialization**: Data can be properly encoded/decoded

## Test Structure

### `contract_test.go`
Tests the data contract (request/response structures):
- `TestRegisterRequest_Contract`: Validates RegisterRequest JSON serialization
- `TestLoginRequest_Contract`: Validates LoginRequest JSON serialization
- `TestAuthResponse_Contract`: Validates AuthResponse JSON serialization
- `TestProfileUpdateRequest_Contract`: Validates ProfileUpdateRequest JSON serialization
- `TestPasswordChangeRequest_Contract`: Validates PasswordChangeRequest JSON serialization
- `TestUser_Contract`: Validates User entity JSON serialization
- `TestProfile_Contract`: Validates Profile entity JSON serialization
- `TestBackwardCompatibility`: Ensures old response formats still work

### `http_contract_test.go`
Tests the HTTP contract (endpoints, status codes, headers):
- `TestRegisterEndpoint_Contract`: Validates Register endpoint HTTP contract
- `TestLoginEndpoint_Contract`: Validates Login endpoint HTTP contract
- `TestRefreshTokenEndpoint_Contract`: Validates RefreshToken endpoint HTTP contract
- `TestLogoutEndpoint_Contract`: Validates Logout endpoint HTTP contract
- `TestErrorResponse_Contract`: Validates error response format
- `TestContentType_Contract`: Validates all endpoints return JSON

## Running Contract Tests

```bash
# Run all contract tests
cd backend/auth/server
go test ./internal/contract/... -v

# Run specific test
go test ./internal/contract/... -v -run TestRegisterRequest_Contract

# Run with coverage
go test ./internal/contract/... -v -cover
```

## What Gets Tested

### Request Contracts
- ✅ All required fields are present
- ✅ JSON serialization/deserialization works
- ✅ Field types are correct
- ✅ Validation rules are enforced

### Response Contracts
- ✅ All required fields are present
- ✅ JSON serialization/deserialization works
- ✅ Sensitive fields (password) are hidden
- ✅ Response structure matches API documentation

### HTTP Contracts
- ✅ Correct HTTP status codes (200, 201, 400, 401, etc.)
- ✅ Content-Type is `application/json`
- ✅ Response format follows standard structure
- ✅ Error responses have consistent format

### Backward Compatibility
- ✅ Old response formats can still be parsed
- ✅ New optional fields don't break old clients
- ✅ Required fields remain required

## Benefits

1. **Fast**: No need to spin up database, Redis, or other services
2. **Isolated**: Tests only the service's own contract
3. **Early Detection**: Catches breaking changes before integration
4. **CI-Friendly**: Fast, reliable, parallelizable
5. **Documentation**: Tests serve as living documentation of the API contract

## Adding New Contract Tests

When adding new endpoints or modifying existing ones:

1. **Add request contract test**:
```go
func TestNewRequest_Contract(t *testing.T) {
    request := domains.NewRequest{
        Field: "value",
    }
    
    jsonData, err := json.Marshal(request)
    require.NoError(t, err)
    
    var unmarshaled domains.NewRequest
    err = json.Unmarshal(jsonData, &unmarshaled)
    require.NoError(t, err)
    
    assert.Equal(t, request.Field, unmarshaled.Field)
}
```

2. **Add response contract test**:
```go
func TestNewResponse_Contract(t *testing.T) {
    response := domains.NewResponse{
        Data: "value",
    }
    
    jsonData, err := json.Marshal(response)
    require.NoError(t, err)
    
    var jsonMap map[string]interface{}
    err = json.Unmarshal(jsonData, &jsonMap)
    require.NoError(t, err)
    
    assert.Contains(t, jsonMap, "data")
}
```

3. **Add HTTP contract test**:
```go
func TestNewEndpoint_Contract(t *testing.T) {
    app := fiber.New()
    app.Post("/api/v1/auth/new", handler.New)
    
    body, _ := json.Marshal(request)
    req := httptest.NewRequest("POST", "/api/v1/auth/new", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    
    resp, _ := app.Test(req)
    assert.Equal(t, 200, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}
```

## CI Integration

Contract tests should run in CI on every commit:

```yaml
# .github/workflows/contract-tests.yml
- name: Run Contract Tests
  run: |
    cd backend/auth/server
    go test ./internal/contract/... -v
```

## Related Documentation

- [API Documentation](../../../../README.md)
- [Integration Tests](../integration/README.md)
- [Service Tests](../domains/service_test.go)

