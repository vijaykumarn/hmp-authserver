# OAuth2 Production Deployment Checklist

## 🔐 Google OAuth2 Setup

### Google Cloud Console
- [ ] Create/Select Google Cloud Project
- [ ] Enable Google+ API or Google Identity API
- [ ] Create OAuth 2.0 Client ID (Web Application)
- [ ] Configure **Authorized redirect URIs**:
  - Development: `http://localhost:8080/login/oauth2/code/google`
  - Production: `https://yourdomain.com/login/oauth2/code/google`
- [ ] Copy Client ID and Client Secret

### OAuth2 Credentials
- [ ] Set `GOOGLE_CLIENT_ID` environment variable
- [ ] Set `GOOGLE_CLIENT_SECRET` environment variable
- [ ] Verify credentials are not hardcoded in application.properties

## 🌐 Environment Configuration

### Required Environment Variables
```bash
# Application URLs
APP_BASE_URL=https://auth.yourdomain.com
FRONTEND_URL=https://app.yourdomain.com

# Google OAuth2
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Database
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/hmp_db
SPRING_DATASOURCE_USERNAME=hmp_app
SPRING_DATASOURCE_PASSWORD=your-secure-password

# Spring Profile
SPRING_PROFILES_ACTIVE=production
```

### Production Profile Settings
- [ ] Enable HTTPS-only cookies: `server.servlet.session.cookie.secure=true`
- [ ] Set SameSite policy: `server.servlet.session.cookie.same-site=strict`
- [ ] Configure proper CORS origins
- [ ] Disable SQL logging in production
- [ ] Set appropriate log levels

## 🔒 Security Configuration

### HTTPS Requirements
- [ ] SSL/TLS certificate installed
- [ ] All OAuth2 redirect URIs use HTTPS
- [ ] Frontend application served over HTTPS
- [ ] Secure cookie flags enabled

### CSRF Protection
- [ ] CSRF tokens enabled for OAuth2 flows
- [ ] Frontend handles CSRF tokens properly
- [ ] Test CSRF protection with tools

### Rate Limiting
- [ ] OAuth2 rate limits configured for production
- [ ] Monitor rate limiting effectiveness
- [ ] Consider Redis for distributed rate limiting

## 📊 Monitoring & Logging

### Audit Logging
- [ ] OAuth2 audit logs enabled
- [ ] Log aggregation configured (ELK, Splunk, etc.)
- [ ] Security event alerting setup
- [ ] PII masking in logs verified

### Health Checks
- [ ] OAuth2 health check endpoint
- [ ] Google OAuth2 connectivity monitoring
- [ ] Database connectivity monitoring
- [ ] Session storage monitoring

### Metrics
- [ ] OAuth2 success/failure rates
- [ ] Rate limiting metrics
- [ ] Session creation/invalidation metrics
- [ ] User registration via OAuth2 metrics

## 🧪 Testing

### Functional Testing
- [ ] OAuth2 login flow works end-to-end
- [ ] Email conflict handling works
- [ ] Session creation and validation works
- [ ] Rate limiting triggers correctly
- [ ] Error handling displays user-friendly messages

### Security Testing
- [ ] CSRF protection tested
- [ ] State parameter validation tested
- [ ] Session fixation protection verified
- [ ] Concurrent session limits enforced
- [ ] IP address validation (if enabled)

### Performance Testing
- [ ] OAuth2 flow under load
- [ ] Database session queries optimized
- [ ] Rate limiting performance acceptable
- [ ] Memory usage during OAuth2 peaks

## 🚀 Deployment Steps

### Pre-Deployment
1. [ ] Run all tests in production-like environment
2. [ ] Verify Google OAuth2 credentials
3. [ ] Check database migrations
4. [ ] Validate environment variables
5. [ ] Test OAuth2 configuration validation

### Deployment
1. [ ] Deploy with `SPRING_PROFILES_ACTIVE=production`
2. [ ] Verify application starts successfully
3. [ ] Check OAuth2 configuration validation logs
4. [ ] Test basic OAuth2 flow
5. [ ] Monitor application logs for errors

### Post-Deployment
1. [ ] Verify OAuth2 login works from production frontend
2. [ ] Test rate limiting behavior
3. [ ] Verify audit logs are generated
4. [ ] Check session management works
5. [ ] Monitor error rates and performance

## 🔧 Troubleshooting

### Common Issues
- **"OAuth2 client-id is not configured"**: Set `GOOGLE_CLIENT_ID` environment variable
- **"redirect_uri_mismatch"**: Update Google Console with correct redirect URI
- **CSRF token missing**: Ensure frontend requests CSRF token
- **Session not created**: Check SessionService logs and database connectivity
- **Rate limiting too aggressive**: Adjust `app.oauth2.rate-limit.*` properties

### Verification Commands
```bash
# Check OAuth2 configuration
curl -k https://yourdomain.com/api/auth/oauth2/authorization-url/google

# Test CSRF endpoint
curl -k https://yourdomain.com/api/auth/csrf-token

# Check application health
curl -k https://yourdomain.com/actuator/health
```

## 📋 Security Review

### Before Go-Live
- [ ] Security team review completed
- [ ] Penetration testing performed
- [ ] OAuth2 flow security validated
- [ ] Session management security verified
- [ ] Rate limiting effectiveness confirmed
- [ ] Audit logging completeness verified
- [ ] Compliance requirements met (GDPR, etc.)

### Ongoing Security
- [ ] Regular security updates scheduled
- [ ] OAuth2 dependency updates monitored
- [ ] Security incident response plan updated
- [ ] Regular security audits scheduled