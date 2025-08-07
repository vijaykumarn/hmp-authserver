# HMP Authorization Server

## How to test google oauth integration

## Next Steps to Test Phase 1 - Basic Google OAuth2 Login

### 1. **Get Google OAuth2 Credentials**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Google+ API (or Google Identity API)
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Configure:
    - **Application type**: Web application
    - **Authorized redirect URIs**: `http://localhost:8080/login/oauth2/code/google`
6. Copy the **Client ID** and **Client Secret**

### 2. **Set Environment Variables**

```bash
export GOOGLE_CLIENT_ID="your-actual-google-client-id"
export GOOGLE_CLIENT_SECRET="your-actual-google-client-secret"
```

Or add to your IDE run configuration.

### 3. **Run Your Application**

Start your Spring Boot app and verify logs show:
- OAuth2 client registration loaded
- No errors about missing OAuth2 configuration

### 4. **Test the OAuth2 Flow**

**Test 1: Get Authorization URL**
```bash
curl -X GET http://localhost:8080/api/auth/oauth2/authorization-url/google \
  -H "Content-Type: application/json" \
  --cookie-jar cookies.txt
```

**Test 2: Manual OAuth2 Flow**
1. Open browser: `http://localhost:8080/oauth2/authorization/google`
2. Should redirect to Google login
3. After Google auth, should redirect back and create session
4. Check database for new user and session records

### 5. **Frontend Integration (Vite)**

In your frontend, add a "Sign in with Google" button:

```typescript
// Get Google auth URL
const response = await fetch('/api/auth/oauth2/authorization-url/google', {
  credentials: 'include'
});
const data = await response.json();

// Redirect to Google OAuth
window.location.href = data.data.authorizationUrl;
```

### 6. **Verify Database Records**

After successful OAuth2 login, check:

```sql
-- Check new OAuth2 user was created
SELECT id, username, email, provider, provider_id, email_verified 
FROM hmp.users 
WHERE provider = 'google';

-- Check session was created
SELECT session_id, user_id, ip_address, remember_me, is_active 
FROM hmp.user_sessions 
WHERE is_active = true;
```

### 7. **Test Session Security**

Verify your existing session security works for OAuth2 users:
- Access protected endpoints with the session cookie
- Test IP validation (if enabled)
- Test concurrent session limits


---

## Outstanding Issues

### 9. **Email Service Not Implemented**
**Location:** `EmailServiceImpl`  
**Issue:** Only logs messages, doesn't send actual emails.  
**Impact:** Users won't receive verification or reset emails.

### 10. **Missing Input Validation**
**Location:** Multiple controllers  
**Issue:** Some endpoints lack proper validation (e.g., session endpoints).  
**Impact:** Potential security vulnerabilities.

#### 🔧 **MEDIUM PRIORITY** (Improvement Opportunities)

### 11. **Exception Handling Inconsistency**
**Location:** `GlobalExceptionHandler`  
**Issue:** Different response formats for similar exception types.  
**Suggestion:** Standardize all error responses to use the same `ApiResponse` format.

### 12. **Caching Issues**
**Location:** `UserServiceImpl` `@Cacheable` annotations  
**Issue:** No cache configuration defined, and cache eviction strategy is incomplete.  
**Suggestion:** Add proper cache configuration and implement comprehensive eviction strategy.

### 13. **Database Schema Hardcoding**
**Location:** All entities with `schema = "hmp"`  
**Issue:** Schema is hardcoded, making it less flexible for different environments.  
**Suggestion:** Use configuration properties for schema names.

### 14. **Session Validation Configuration**
**Location:** `SessionServiceImpl` properties  
**Issue:** Security settings should be environment-dependent (dev vs prod).  
**Suggestion:** Use profiles for different security levels.

### 15. **Missing API Documentation**
**Location:** Throughout controllers  
**Issue:** No OpenAPI/Swagger documentation.  
**Suggestion:** Add comprehensive API documentation.

### 16. **Logout Reason Enum Usage**
**Location:** `SessionServiceImpl`  
**Issue:** Hard-coded logout reason strings instead of using the enum consistently.  
**Suggestion:** Use `LogoutReason` enum everywhere.

### 17. **Token Expiry Configuration**
**Location:** `TokenServiceImpl`  
**Issue:** Hard-coded 1-hour expiry for all token types.  
**Suggestion:** Make token expiry configurable per token type.

#### 🎯 **LOW PRIORITY** (Nice to Have)

### 18. **Async Event Processing**
**Location:** Event listeners  
**Issue:** Events are processed asynchronously but no error handling for failures.  
**Suggestion:** Add retry mechanism and dead letter queues.

### 19. **Monitoring and Metrics**
**Location:** Throughout application  
**Issue:** No metrics or monitoring for authentication flows.  
**Suggestion:** Add Micrometer metrics for login attempts, failures, etc.

### 20. **Test Coverage**
**Location:** Test directory  
**Issue:** Only one basic test exists.  
**Suggestion:** Add comprehensive unit and integration tests.

### 21. **Database Migration Scripts**
**Location:** Missing  
**Issue:** No Flyway or Liquibase migrations for database schema.  
**Suggestion:** Add proper database migration management.

### 22. **Environment-Specific Configuration**
**Location:** `application.properties`  
**Issue:** All configurations in single file, not optimized for different environments.  
**Suggestion:** Split into environment-specific property files.

### 23. **Logging Improvements**
**Location:** Throughout application  
**Issue:** Inconsistent logging levels and sensitive data might be logged.  
**Suggestion:** Standardize logging and ensure no sensitive data is logged.

### 24. **Connection Pool Configuration**
**Location:** Database configuration  
**Issue:** No explicit connection pool configuration.  
**Suggestion:** Add HikariCP configuration for better performance.

### 25. **Session Cookie Security**
**Location:** `SessionServiceImpl.configureSecureSessionCookie()`  
**Issue:** `secure` flag is hardcoded to `false`.  
**Suggestion:** Make it environment-dependent (true for production).

## 🏗️ **ARCHITECTURAL IMPROVEMENTS**

### 26. **Service Layer Abstraction**
**Issue:** Some services have tight coupling to specific implementations.  
**Suggestion:** Improve abstraction and dependency injection patterns.

### 27. **Error Response Standardization**
**Issue:** Mixed error response formats across different exception handlers.  
**Suggestion:** Create a unified error response structure.

### 28. **Security Configuration Modularization**
**Issue:** Large security configuration class handling multiple concerns.  
**Suggestion:** Break into smaller, focused configuration classes.

### 29. **Event-Driven Architecture Enhancement**
**Issue:** Limited use of domain events for business processes.  
**Suggestion:** Expand event-driven patterns for better decoupling.

### 30. **Repository Pattern Enhancement**
**Issue:** Some complex queries could be better organized.  
**Suggestion:** Consider using specification pattern for complex queries.

---

