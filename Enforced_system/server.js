const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const HTTPS_PORT = 443;
const HTTP_PORT = 80;
const HOST = '0.0.0.0';

// Rate limiting configuration
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_RESET_TIME = 60 * 60 * 1000; // 1 hour

// SSL configuration
const credentials = {
    key: fs.readFileSync('./certificates/private.key'),
    cert: fs.readFileSync('./certificates/certificate.pem')
};

// Encryption configuration
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = crypto.randomBytes(32);
const IV_LENGTH = 16;

// Encryption utility functions
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Users array with hashed passwords
let users = [
    { 
        id: 1, 
        username: 'giampaolo', 
        password: '$2a$10$RIFCAssVanYeC4uDonP.nOqoHoqssNnOz8Cko2Bb7aIgGTMBAbJYi', // hashed 'adminpass'
        role: 'admin',
        personalData: {
            creditCard: encrypt("4539-7894-5698-1234"),
            codiceFiscale: encrypt("RSSMRA80A01H501U"),
            iban: encrypt("IT60X0542811101000000123456")
        }
    },
    { 
        id: 2, 
        username: 'paolo', 
        password: '$2a$10$CZdmu1AJhSNrhjK5FYPWEuhF93akdDqBYMcTwPdacPrwx7dRSzdOO', // hashed 'password1'
        role: 'standard',
        personalData: {
            creditCard: encrypt("4532-1234-5678-9012"),
            codiceFiscale: encrypt("VRDLGU85B15H501V"),
            iban: encrypt("IT60X0542811101000000789012")
        }
    },
    { 
        id: 3, 
        username: 'sergio', 
        password: '$2a$10$zFjpyrXl07yRcnkQMh7ZoeTPmdtuhle4MrT432f92f2.sgQUnimRm', // hashed 'password2'
        role: 'standard',
        personalData: {
            creditCard: encrypt("4532-7891-2345-6789"),
            codiceFiscale: encrypt("BRNGNN82C14H501W"),
            iban: encrypt("IT60X0542811101000000456789")
        }
    }
];

app.use(express.json());
app.use(express.static('public'));

function checkLoginAttempts(username, ip) {
    const key = `${username}-${ip}`;
    const attempts = loginAttempts.get(key) || { count: 0, firstAttempt: Date.now(), locked: false };
    
    if (Date.now() - attempts.firstAttempt > ATTEMPT_RESET_TIME) {
        attempts.count = 0;
        attempts.firstAttempt = Date.now();
        attempts.locked = false;
    }
    
    if (attempts.locked) {
        if (Date.now() - attempts.lockTime < LOCK_TIME) {
            const remainingTime = Math.ceil((LOCK_TIME - (Date.now() - attempts.lockTime)) / 1000 / 60);
            return {
                allowed: false,
                message: `Account temporarily locked. Try again in ${remainingTime} minutes.`
            };
        } else {
            attempts.locked = false;
            attempts.count = 0;
        }
    }
    
    if (attempts.count >= MAX_ATTEMPTS) {
        attempts.locked = true;
        attempts.lockTime = Date.now();
        loginAttempts.set(key, attempts);
        return {
            allowed: false,
            message: 'Too many failed attempts. Account locked for 15 minutes.'
        };
    }
    
    return { allowed: true };
}

function updateLoginAttempts(username, ip, success) {
    const key = `${username}-${ip}`;
    const attempts = loginAttempts.get(key) || { count: 0, firstAttempt: Date.now() };
    
    if (success) {
        loginAttempts.delete(key);
    } else {
        attempts.count++;
        loginAttempts.set(key, attempts);
    }
}

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip;
    
    const rateCheck = checkLoginAttempts(username, ip);
    if (!rateCheck.allowed) {
        return res.status(429).json({ message: rateCheck.message });
    }

    const user = users.find(u => u.username === username);
    
    if (!user) {
        updateLoginAttempts(username, ip, false);
        return res.status(401).json({ message: 'Credenziali non valide' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    
    if (validPassword) {
        updateLoginAttempts(username, ip, true);
        const token = jwt.sign({ 
            id: user.id,
            username: user.username, 
            role: user.role 
        }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        updateLoginAttempts(username, ip, false);
        res.status(401).json({ message: 'Credenziali non valide' });
    }
});

function authenticate(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: 'Token mancante' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: 'Token scaduto' });
        }
        return res.status(401).json({ message: 'Token non valido' });
    }
}

app.get('/api/users/:userId/data', authenticate, (req, res) => {
    const requestedId = parseInt(req.params.userId);
    const user = users.find(u => u.id === requestedId);
    
    if (!user) {
        return res.status(404).json({ message: 'Utente non trovato' });
    }

    if (req.user.role !== 'admin' && req.user.id !== requestedId) {
        return res.status(403).json({ message: 'Non autorizzato ad accedere a questi dati' });
    }
    
    const decryptedData = {
        creditCard: decrypt(user.personalData.creditCard),
        codiceFiscale: decrypt(user.personalData.codiceFiscale),
        iban: decrypt(user.personalData.iban)
    };
    
    res.json({ personalData: decryptedData });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (req.user.role === 'admin') {
        const usersList = users.map(u => ({
            id: u.id,
            username: u.username,
            role: u.role
        }));
        res.json({ users: usersList });
    } else {
        res.status(403).json({ message: 'Accesso negato' });
    }
});

app.delete('/api/admin/users/:userId', authenticate, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Accesso negato' });
    }

    const userIdToDelete = parseInt(req.params.userId);
    const userIndex = users.findIndex(u => u.id === userIdToDelete);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'Utente non trovato' });
    }

    if (users[userIndex].role === 'admin') {
        return res.status(403).json({ message: 'Non puoi eliminare un admin' });
    }

    users.splice(userIndex, 1);
    res.json({ message: 'Utente eliminato con successo' });
});

const httpApp = express();
httpApp.get('*', (req, res) => {
    res.redirect('https://' + req.headers.host + req.url);
});

const httpsServer = https.createServer(credentials, app);
const httpServer = http.createServer(httpApp);

httpServer.listen(HTTP_PORT, HOST, () => {
    console.log(`HTTP Server running on http://${HOST}:${HTTP_PORT} (redirecting to HTTPS)`);
});

httpsServer.listen(HTTPS_PORT, HOST, () => {
    console.log(`HTTPS Server running on https://${HOST}:${HTTPS_PORT}`);
});
