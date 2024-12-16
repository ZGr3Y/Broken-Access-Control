# IDOR Vulnerability Demo

Questa è un'applicazione dimostrativa creata per illustrare una vulnerabilità di tipo Broken Access Control, specificamente un IDOR (Insecure Direct Object Reference). Il progetto è stato sviluppato esclusivamente per scopi educativi e di ricerca.

## ⚠️ Disclaimer

Questo progetto contiene **vulnerabilità di sicurezza intenzionali** ed è stato creato solo per scopi dimostrativi ed educativi. Non utilizzare in produzione o in ambienti reali.

## 📝 Descrizione

L'applicazione simula un sistema di gestione utenti con dati sensibili (informazioni bancarie e fiscali). Include:
- Sistema di autenticazione con JWT
- Pannello admin per la gestione utenti
- API per accedere ai dati personali
- Vulnerabilità IDOR dimostrativa

## 🔧 Tecnologie Utilizzate

- Node.js
- Express.js
- JWT (JSON Web Tokens)
- HTML/CSS/JavaScript (Frontend)

## 🚀 Installazione

```bash
# Clona il repository
git clone https://github.com/[your-username]/idor-demo

# Installa le dipendenze
cd idor-demo
npm install

# Avvia il server
node server.js
```

L'applicazione sarà disponibile su `http://localhost:3000`

## 👥 Utenti Demo

```javascript
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

| Soggetto/Oggetto | Propri Dati Personali | Dati Personali Altri Utenti | Lista Utenti | Eliminazione Utenti | Admin Panel |
|------------------|----------------------|---------------------------|--------------|-------------------|-------------|
| Admin            | R                    | R                         | R            | D                 | R           |
| Utente Standard  | R                    | X                         | X            | X                 | X           |
| Non Autenticato  | X                    | X                         | X            | X                 | X           |

Legenda:
- R: Read (Lettura)
- D: Delete (Eliminazione)
- X: Nessun accesso

## 🔍 Vulnerabilità IDOR

### Descrizione
La vulnerabilità permette a un utente standard di accedere ai dati personali di altri utenti modificando l'ID nella richiesta API.

### Come Riprodurre
1. Login come utente standard (es. paolo/password1)
2. Intercetta la richiesta a `/api/users/2/data`
3. Modifica l'ID nella richiesta (es. da 2 a 1 per accedere ai dati dell'admin)



## 📁 Struttura del Progetto

```
idor-demo/
├── public/
│   ├── index.html
│   ├── script.js
│   └── style.css
├── server.js
├── package.json
└── README.md
```

## 🛡️ Best Practices di Sicurezza

Per proteggere un'applicazione da vulnerabilità IDOR:
1. Implementare controlli di autorizzazione rigorosi
2. Verificare sempre la proprietà delle risorse
3. Utilizzare identificatori indiretti o UUID
4. Implementare il principio del minimo privilegio

## 👥 Contribuire

Questo è un progetto dimostrativo, ma suggerimenti e miglioramenti sono benvenuti attraverso issues e pull requests.

## 📄 Licenza

[MIT License](LICENSE)

## ✍️ Autore

Paolo Maria Scarlata
