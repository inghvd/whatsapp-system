const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const db = new sqlite3.Database('./whatsapp_data.db', (err) => {
    if (err) console.error('❌ Error BD:', err);
    else console.log('💾 Base de Datos SaaS Conectada');
});

db.serialize(() => {
    // 1. Usuarios
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'agent'
    )`);

    // Admin por defecto: admin / 1234
    const hash = bcrypt.hashSync('1234', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', ?, 'admin')`, [hash]);

    // 2. Contactos (Privados por usuario)
    db.run(`CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        phone TEXT,
        name TEXT,
        UNIQUE(user_id, phone)
    )`);

    // 3. Logs (Historial)
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        type TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

module.exports = db;
