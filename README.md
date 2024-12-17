# Broken Access Control Vulnerabilities Demo

This is a demonstration application created to illustrate three different manifestations of Broken Access Control vulnerabilities:
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation via JWT Manipulation
- Authentication Bypass via Man-in-the-Middle

This project has been developed exclusively for educational and research purposes.

## ⚠️ Disclaimer
This project contains **intentional security vulnerabilities** and was created for demonstration and educational purposes only. Do not use in production or real environments.

## 📝 Description
The application simulates a user management system with sensitive data (banking and fiscal information) that demonstrates three different ways Broken Access Control can manifest. It includes:
* Vulnerable JWT authentication system
* Admin panel for user management
* API for accessing personal data
* Multiple Broken Access Control vulnerabilities

## 🔧 Technologies Used
* Node.js
* Express.js
* JWT (JSON Web Tokens)
* HTML/CSS/JavaScript (Frontend)

## 🚀 Installation
```bash
# Clone the repository
git clone https://github.com/[your-username]/broken-access-control-demo

# Install dependencies
cd broken-access-control-demo
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

## 🔍 Broken Access Control Vulnerabilities

### 1. Horizontal Privilege Bypass via IDOR
This vulnerability allows users to access resources belonging to other users at the same privilege level.

How to Reproduce:
1. Login as a standard user (e.g., paolo/password1)
2. Intercept the request to `/api/users/2/data`
3. Modify the ID in the request (e.g., from 2 to 3 to access another user's data)

### 2. Vertical Privilege Escalation via JWT
This vulnerability allows users to escalate their privileges to a higher access level.

How to Reproduce:
1. Login as a standard user and obtain the JWT token
2. Decode the token payload (you can use jwt.io)
3. Modify the 'role' field from 'standard' to 'admin'
4. The server will accept the manipulated token, granting admin privileges

### 3. Authentication Bypass via MITM
This vulnerability allows attackers to intercept and reuse authentication tokens to impersonate legitimate users.

How to Reproduce:
1. Use a traffic interception tool (e.g., Wireshark)
2. Monitor HTTP traffic between client and server
3. Capture JWT tokens being transmitted
4. Use the captured token to authenticate as the legitimate user

## 📁 Project Structure
```
Broken-Access-Control/
├── Vulnerable_system/
│   ├── public/
│   │   ├── index.html
│   │   ├── script.js
│   │   └── style.css
│   └── server.js
├── LICENSE
└── README.md
```

## 🛡️ Security Best Practices
To protect against Broken Access Control:

1. Access Control Design:
   * Implement role-based access control (RBAC)
   * Apply the principle of least privilege
   * Deny by default, allow by exception
   * Implement proper session management

2. Implementation Measures:
   * Use indirect object references
   * Implement strong authorization checks at each level
   * Properly validate and verify JWT tokens
   * Use secure session handling

3. Transport Security:
   * Implement HTTPS/TLS
   * Use secure token transmission methods
   * Implement proper session timeouts
   * Use secure cookie flags

## 👥 Contributing
This is a demonstration project, but suggestions and improvements are welcome through issues and pull requests.

## 📄 License
MIT License

## ✍️ Author
Paolo Maria Scarlata
