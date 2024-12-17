# IDOR, JWT, and MITM Vulnerabilities Demo

This is a demonstration application created to illustrate several common security vulnerabilities:
- Broken Access Control (IDOR - Insecure Direct Object Reference)
- JWT Token Manipulation
- Man-in-the-Middle (MITM) Attacks

This project has been developed exclusively for educational and research purposes.

## ⚠️ Disclaimer
This project contains **intentional security vulnerabilities** and was created for demonstration and educational purposes only. Do not use in production or real environments.

## 📝 Description
The application simulates a user management system with sensitive data (banking and fiscal information). It includes:
* Vulnerable JWT authentication system
* Admin panel for user management
* API for accessing personal data
* Multiple demonstration vulnerabilities

## 🔧 Technologies Used
* Node.js
* Express.js
* JWT (JSON Web Tokens)
* HTML/CSS/JavaScript (Frontend)

## 🚀 Installation
```bash
# Clone the repository
git clone https://github.com/[your-username]/security-vulnerabilities-demo

# Install dependencies
cd security-vulnerabilities-demo
npm install

# Start the server
node server.js
```

The application will be available at `http://localhost:3000`

## 👥 Demo Users
```
Admin:
- Username: giampaolo
- Password: adminpass

Standard Users:
- Username: paolo
- Password: password1
- Username: sergio
- Password: password2
```

## 🔒 Access Control Matrix
Subject/Object | Own Personal Data | Others' Personal Data | User List | User Deletion | Admin Panel
---------------|------------------|---------------------|-----------|---------------|-------------
Admin          | R                | R                   | R         | D             | R
Standard User  | R                | X                   | X         | X             | X
Unauthenticated| X                | X                   | X         | X             | X

Legend:
* R: Read
* D: Delete
* X: No access

## 🔍 Present Vulnerabilities

### 1. IDOR (Insecure Direct Object Reference)
This vulnerability allows a standard user to access personal data of other users by modifying the ID in the API request.

How to Reproduce:
1. Login as a standard user (e.g., paolo/password1)
2. Intercept the request to `/api/users/2/data`
3. Modify the ID in the request (e.g., from 2 to 1 to access admin's data)

### 2. JWT Token Manipulation
The JWT implementation has vulnerabilities that allow token manipulation.

How to Reproduce:
1. Login and obtain the JWT token
2. Decode the token payload (you can use jwt.io)
3. Modify the 'role' field from 'standard' to 'admin'
4. The server will accept the manipulated token due to lack of verification

### 3. Man-in-the-Middle (MITM)
The application is vulnerable to MITM attacks due to lack of HTTPS.

How to Reproduce:
1. Use a traffic interception tool (e.g., Wireshark)
2. Monitor HTTP traffic between client and server
3. JWT tokens and sensitive data are visible in plain text

## 📁 Project Structure
```
security-vulnerabilities-demo/
├── public/
│   ├── index.html
│   ├── script.js
│   └── style.css
├── server.js
├── package.json
└── README.md
```

## 🛡️ Security Best Practices
To protect an application from these vulnerabilities:

1. IDOR Protection:
   * Implement rigorous authorization controls
   * Always verify resource ownership
   * Use indirect identifiers or UUIDs
   * Implement the principle of least privilege

2. JWT Protection:
   * Use a strong secret key
   * Implement token verification
   * Use a whitelist of valid tokens
   * Implement token rotation

3. MITM Protection:
   * Implement HTTPS/TLS
   * Use HSTS
   * Implement certificate pinning
   * Monitor and validate certificates

## 👥 Contributing
This is a demonstration project, but suggestions and improvements are welcome through issues and pull requests.

## 📄 License
GPL License

## ✍️ Author
Paolo Maria Scarlata
