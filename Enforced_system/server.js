const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256 bit key
const IV_LENGTH = 16; // For AES-256
const HOST = '0.0.0.0';

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

app.use(express.json());
app.use(express.static('public'));

// Initialize users with hashed passwords and encrypted sensitive data
let users = [
    { 
        id: 1, 
        username: 'giampaolo', 
        password: '$2a$10$E8REZ35wOj1UL7OKK4R6v.X868plNT.mKOpGh7FOUvxGF3qiGhV0K', // hashed 'adminpass'
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
        password: '$2a$10$izXSbOhPRsSlzjLqrXPvl.osG6mzTsp8W8eAH76QUk7K35mdZSm1G', // hashed 'password1'
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
        password: '$2a$10$gyj.ef.zYaYKAZMdOJI1ruZdv3Ytcj.yT6KALURlJRu4X9Xd4rK1O', // hashed 'password2'
        role: 'standard',
        personalData: {
            creditCard: encrypt("4532-7891-2345-6789"),
            codiceFiscale: encrypt("BRNGNN82C14H501W"),
            iban: encrypt("IT60X0542811101000000456789")
        }
    }
];

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ message: 'Credenziali non valide' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    
    if (validPassword) {
        const token = jwt.sign({ 
            id: user.id,
            username: user.username, 
            role: user.role 
        }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
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
    
    // Decrypt data before sending
    const decryptedData = {
        creditCard: decrypt(user.personalData.creditCard),
        codiceFiscale: decrypt(user.personalData.codiceFiscale),
        iban: decrypt(user.personalData.iban)
    };
    
    res.json({ personalData: decryptedData });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (req.user.role === 'admin') {
        const userList = users.map(u => ({
            id: u.id,
            username: u.username,
            role: u.role
        }));
        res.json({ users: userList });
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

app.listen(PORT, HOST, () => {
    console.log(`Server in ascolto su http://${HOST}:${PORT}`);
});
