# Security Enhancements - Brute Force & DOS Protection

## Overview
Added comprehensive security measures to protect against brute force attacks and Denial of Service (DOS) attempts.

## Implemented Features

### 1. **Brute Force Protection**

#### Account Lockout Mechanism
- **Maximum Login Attempts**: 5 failed attempts
- **Lockout Duration**: 15 minutes
- **Tracking**: Per-username attempt counter
- **Auto-Reset**: Lockout expires automatically after duration

#### Features:
- Tracks failed login attempts per username
- Locks account after exceeding threshold
- Displays remaining attempts to user
- Shows lockout time remaining
- Logs all lockout events to audit log
- Automatically resets counter on successful login

#### User Experience:
```
Attempt 1-4: "Invalid username or password. X attempts remaining."
Attempt 5: "Account locked due to 5 failed attempts. Try again in 15 minutes."
During lockout: "Account locked. Try again in X minutes."
```

### 2. **Rate Limiting (DOS Prevention)**

#### Global Rate Limits
- **200 requests per day** per IP address
- **50 requests per hour** per IP address

#### Endpoint-Specific Limits

| Endpoint | Rate Limit | Purpose |
|----------|------------|---------|
| `/login` | 10 per minute | Prevent brute force |
| `/api/upload` | 10 per minute | Prevent upload spam |
| `/api/anonymize` | 20 per hour | Limit expensive operations |
| `/api/audit-logs` | 30 per minute | Prevent log flooding |

#### Rate Limit Headers
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Time when limit resets

### 3. **Security Event Logging**

All security events are logged with:
- Event type (ACCOUNT_LOCKED, RATE_LIMIT_EXCEEDED, LOGIN_ATTEMPT_LOCKED)
- Username/IP address
- Timestamp
- Additional context (attempts remaining, lockout duration)

### 4. **Error Handling**

#### 429 Rate Limit Exceeded
- Custom error page (`templates/429.html`)
- JSON response for API endpoints
- HTML page for browser requests
- Logs security event

## Configuration

### Customization Options

Edit `app.py` to adjust settings:

```python
# Brute force protection settings
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

# Rate limiting settings
default_limits=["200 per day", "50 per hour"]
```

### Endpoint Rate Limits

Modify decorators on specific routes:

```python
@limiter.limit("10 per minute")  # Adjust as needed
def your_endpoint():
    pass
```

## Monitoring & Administration

### View Security Events

Check audit logs for security-related events:
```bash
grep "RATE_LIMIT_EXCEEDED\|ACCOUNT_LOCKED\|LOGIN_ATTEMPT_LOCKED" anonykit_audit.log
```

### Reset Account Lockout

Currently stored in memory. To reset:
1. Restart the application
2. Or wait for lockout duration to expire

**Note**: For production, implement persistent storage (Redis/Database) for lockout tracking across server restarts.

## Production Recommendations

### 1. **Persistent Storage**
Replace in-memory storage with Redis or database:
```python
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)
```

### 2. **IP-Based Blocking**
Consider implementing IP blocklisting for repeated violations:
- Use Flask-IPBan or similar
- Block IPs after multiple lockouts
- Configure firewall rules

### 3. **CAPTCHA Integration**
Add CAPTCHA after failed login attempts:
- Google reCAPTCHA
- hCaptcha
- Implement after 3 failed attempts

### 4. **Monitoring & Alerts**
- Set up real-time alerts for security events
- Monitor rate limit violations
- Track patterns of abuse
- Implement SIEM integration

### 5. **Load Balancer Integration**
If using load balancer:
- Configure rate limiting at LB level
- Use distributed rate limiting (Redis)
- Ensure IP address is correctly forwarded

## Testing

### Test Brute Force Protection

1. **Attempt multiple failed logins:**
   ```bash
   # Try logging in with wrong password 5 times
   # Account should be locked
   ```

2. **Verify lockout message:**
   - Should show remaining time
   - Should prevent login during lockout

3. **Wait for lockout expiration:**
   - After 15 minutes, login should work again

### Test Rate Limiting

1. **Rapid API requests:**
   ```bash
   # Make 11 rapid requests to /login
   # 11th request should return 429
   ```

2. **Check headers:**
   ```bash
   curl -I http://localhost:5000/api/audit-logs
   # Look for X-RateLimit-* headers
   ```

## Security Considerations

### Strengths
✅ Per-user account lockout prevents brute force
✅ Rate limiting prevents DOS attacks
✅ Comprehensive audit logging
✅ Graduated user feedback (attempts remaining)
✅ Automatic lockout expiration

### Limitations
⚠️ In-memory storage (resets on restart)
⚠️ No distributed rate limiting
⚠️ No IP-based banning
⚠️ No CAPTCHA integration
⚠️ No geographic blocking

### Future Enhancements
- Persistent lockout storage (Redis/Database)
- Progressive delays (exponential backoff)
- IP reputation checking
- Geographic anomaly detection
- Machine learning-based threat detection

## Dependencies

Added to `requirements.txt`:
```
Flask-Limiter>=3.5.0
```

## Files Modified

1. `app.py` - Added rate limiting and brute force protection
2. `requirements.txt` - Added Flask-Limiter dependency
3. `templates/429.html` - Created rate limit error page
4. `SECURITY_ENHANCEMENTS.md` - This documentation

## Compliance

These security measures help with compliance for:
- **GDPR**: Protects against unauthorized access attempts
- **HIPAA**: Security controls for health data systems
- **PCI DSS**: Requirement 8.1.6 (Account lockout)
- **NIST 800-53**: AC-7 (Unsuccessful Login Attempts)

## Support

For issues or questions:
1. Check audit logs for security events
2. Review rate limit headers in responses
3. Monitor application logs
4. Contact system administrator

---

**Implementation Date**: December 1, 2025
**Version**: 2.0
**Status**: Active
