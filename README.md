# IDOR, JWT, and MITM Vulnerabilities Demo

Questa è un'applicazione dimostrativa creata per illustrare diverse vulnerabilità di sicurezza comuni:
- Broken Access Control (IDOR - Insecure Direct Object Reference)
- Manipolazione del token JWT
- Attacchi Man-in-the-Middle (MITM)

Il progetto è stato sviluppato esclusivamente per scopi educativi e di ricerca.

## ⚠️ Disclaimer
Questo progetto contiene **vulnerabilità di sicurezza intenzionali** ed è stato creato solo per scopi dimostrativi ed educativi. Non utilizzare in produzione o in ambienti reali.

## 📝 Descrizione
L'applicazione simula un sistema di gestione utenti con dati sensibili (informazioni bancarie e fiscali). Include:
* Sistema di autenticazione vulnerabile con JWT
* Pannello admin per la gestione utenti
* API per accedere ai dati personali
* Multiple vulnerabilità dimostrative

## 🔧 Tecnologie Utilizzate
* Node.js
* Express.js
* JWT (JSON Web Tokens)
* HTML/CSS/JavaScript (Frontend)

## 🚀 Installazione
```bash
# Clona il repository
git clone https://github.com/[your-username]/security-vulnerabilities-demo

# Installa le dipendenze
cd security-vulnerabilities-demo
npm install

# Avvia il server
node server.js
```

L'applicazione sarà disponibile su `http://localhost:3000`

## 👥 Utenti Demo
```
Admin:
- Username: giampaolo
- Password: adminpass

Utenti Standard:
- Username: paolo
- Password: password1
- Username: sergio
- Password: password2
```

## 🔒 Access Control Matrix
Soggetto/Oggetto | Propri Dati Personali | Dati Personali Altri Utenti | Lista Utenti | Eliminazione Utenti | Admin Panel
-----------------|----------------------|---------------------------|--------------|-------------------|-------------
Admin            | R                    | R                         | R            | D                 | R
Utente Standard  | R                    | X                         | X            | X                 | X
Non Autenticato  | X                    | X                         | X            | X                 | X

Legenda:
* R: Read (Lettura)
* D: Delete (Eliminazione)
* X: Nessun accesso

## 🔍 Vulnerabilità Presenti

### 1. IDOR (Insecure Direct Object Reference)
La vulnerabilità permette a un utente standard di accedere ai dati personali di altri utenti modificando l'ID nella richiesta API.

Come Riprodurre:
1. Login come utente standard (es. paolo/password1)
2. Intercetta la richiesta a `/api/users/2/data`
3. Modifica l'ID nella richiesta (es. da 2 a 1 per accedere ai dati dell'admin)

### 2. Manipolazione del Token JWT
L'implementazione JWT presenta vulnerabilità che permettono la manipolazione del token.

Come Riprodurre:
1. Effettua il login e ottieni il token JWT
2. Decodifica il payload del token (puoi usare jwt.io)
3. Modifica il campo 'role' da 'standard' a 'admin'
4. Il server accetterà il token manipolato per via della mancata verifica

### 3. Man-in-the-Middle (MITM)
L'applicazione è vulnerabile agli attacchi MITM a causa della mancanza di HTTPS.

Come Riprodurre:
1. Utilizza uno strumento di intercettazione del traffico (es. Wireshark)
2. Monitora il traffico HTTP tra client e server
3. I token JWT e i dati sensibili sono visibili in chiaro

## 📁 Struttura del Progetto
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

## 🛡️ Best Practices di Sicurezza
Per proteggere un'applicazione da queste vulnerabilità:

1. Protezione da IDOR:
   * Implementare controlli di autorizzazione rigorosi
   * Verificare sempre la proprietà delle risorse
   * Utilizzare identificatori indiretti o UUID
   * Implementare il principio del minimo privilegio

2. Protezione JWT:
   * Utilizzare una chiave segreta forte
   * Implementare la verifica del token
   * Utilizzare una whitelist di token validi
   * Implementare la rotazione dei token

3. Protezione da MITM:
   * Implementare HTTPS/TLS
   * Utilizzare HSTS
   * Implementare il pinning dei certificati
   * Monitorare e validare i certificati

## 👥 Contribuire
Questo è un progetto dimostrativo, ma suggerimenti e miglioramenti sono benvenuti attraverso issues e pull requests.

## 📄 Licenza
MIT License

## ✍️ Autore
Paolo Maria Scarlata
