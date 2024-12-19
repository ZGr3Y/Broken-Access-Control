# Security Vulnerabilities Guide

This document describes the security vulnerabilities present in this demonstration application. **This is for educational purposes only** and should only be used on this test application.

## ⚠️ Disclaimer
This guide is intended for educational purposes to understand web security vulnerabilities. Do not attempt these techniques on any real-world applications or systems you don't own or have explicit permission to test.

## 🔍 Vulnerability Overview

### 1. IDOR (Insecure Direct Object Reference)
**Description**: The application doesn't properly verify if a user has permission to access requested resources.

**How to exploit**:
1. Login as a standard user (e.g., paolo/password1)
2. Access your user data at `/api/users/2/data`
3. Change the ID in the URL to another user's ID (e.g., `/api/users/1/data` for admin data)
4. The server returns the data without checking permissions

### 2. JWT Token Manipulation
**Description**: The application has multiple JWT security issues including weak token validation.

**How to exploit**:
1. Login and get a valid JWT token
2. Decode the token at jwt.io
3. Modify the payload to change role to "admin"
4. Use the modified token in the Authorization header
5. The server accepts the manipulated token due to using jwt.decode() instead of jwt.verify()

### 3. Man-in-the-Middle (Plain HTTP)
**Description**: The application transmits sensitive data over unencrypted HTTP.

**How to exploit using Wireshark**:
1. Open Wireshark and select network interface
2. Set capture filter: `ip.addr == SERVER_IP && tcp.port == 3000`
3. Capture login requests to see:
   - Plaintext credentials in POST requests
   - JWT tokens in response
   - Sensitive data in subsequent requests
4. Filter specific requests:
   - Login: `http.request.method == "POST" && http.request.uri contains "login"`
   - Protected endpoints: `http contains "Authorization"`

### 4. Replay Attacks
**Description**: The application lacks token freshness validation.

**How to exploit**:
1. Capture a valid request with authorization header using Wireshark
2. Copy the entire request
3. Send it again using cURL or Postman
4. The server accepts the replayed request due to:
   - No token expiration
   - No nonce implementation
   - No token blacklist/whitelist

## 🛡️ Missing Security Controls

1. Token Security:
   - No token expiration (exp claim)
   - No token verification (using decode instead of verify)
   - Empty SECRET_KEY
   - No token blacklist/whitelist

2. Transport Security:
   - No HTTPS
   - No HSTS
   - No certificate pinning
   - Plaintext data transmission

3. Access Controls:
   - No proper authorization checks
   - No resource ownership verification
   - No role-based access control
   - No request rate limiting

4. Data Security:
   - Passwords stored in plaintext
   - Sensitive data not encrypted
   - No input validation
   - No CORS configuration

## 🔒 Recommended Mitigations

1. Implement proper JWT handling:
```javascript
const token = jwt.sign({ 
    id: user.id,
    username: user.username,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + (15 * 60), // 15 min expiration
}, STRONG_SECRET_KEY);
```

2. Add authorization checks:
```javascript
function checkAuthorization(req, res, next) {
    if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Unauthorized access' });
    }
    next();
}
```

3. Enable HTTPS:
```javascript
const https = require('https');
const fs = require('fs');

const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
};

https.createServer(options, app).listen(3000);
```

4. Implement token validation:
```javascript
function authenticate(req, res, next) {
    try {
        const token = req.headers['authorization'];
        const decoded = jwt.verify(token, SECRET_KEY); // Use verify instead of decode
        req.user = decoded;
        next();
    } catch(err) {
        res.status(401).json({ message: 'Invalid token' });
    }
}
```

## 📚 Learning Resources
- OWASP Broken Access Control
- OWASP Authentication Cheatsheet
- OWASP Transport Layer Protection Cheatsheet
- JWT Best Practices

## ⚖️ License
MIT License
