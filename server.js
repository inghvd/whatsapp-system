// --- Dependencias principales ---
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, LocalAuth } = require('whatsapp-web.js');
const QRCode = require('qrcode');
const db = require('./database');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const xlsx = require('xlsx');

// --- Inicialización de servidor ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// 🔧 Puerto dinámico para Render, fijo 3034 en local
const PORT = process.env.PORT || 3034;

// --- Configuración de subida de archivos en memoria ---
const upload = multer({ storage: multer.memoryStorage() });

// --- Middlewares ---
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    // 🔧 Secret dinámico desde variable de entorno
    secret: process.env.SESSION_SECRET || 'secreto_empresa_2025',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000 }
}));

// --- Cliente WhatsApp ---
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: {
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
    }
});

// Generación de QR
client.on('qr', (qr) => {
    console.log('📲 QR GENERADO');
    QRCode.toDataURL(qr, (err, url) => io.emit('qr', { src: url }));
});

// Conexión lista
client.on('ready', () => {
    console.log('✅ WHATSAPP CONECTADO');
    io.emit('ready', { status: 'Conectado' });
});

client.initialize();

// --- Autenticación ---
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Datos incorrectos" });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        res.json({ role: user.role, username: user.username });
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ status: 'ok' });
});

// Middleware de auth
const auth = (req, res, next) => {
    if (!req.session.userId) return res.status(403).json({ error: "Sesión expirada" });
    next();
};

// --- CRUD de Contactos ---
app.post('/add-contact', auth, (req, res) => {
    const { name, phone } = req.body;
    const cleanPhone = phone.replace(/\D/g, '');
    db.run("INSERT OR IGNORE INTO contacts (user_id, phone, name) VALUES (?, ?, ?)", 
        [req.session.userId, cleanPhone, name], 
        (err) => res.json(err ? { error: err.message } : { status: 'Guardado' }));
});

app.post('/update-contact', auth, (req, res) => {
    const { id, name, phone } = req.body;
    const cleanPhone = phone.replace(/\D/g, '');
    db.run("UPDATE contacts SET name = ?, phone = ? WHERE id = ? AND user_id = ?", 
        [name, cleanPhone, id, req.session.userId], 
        (err) => res.json(err ? { error: err.message } : { status: 'Actualizado' }));
});

app.post('/delete-contact', auth, (req, res) => {
    const { id } = req.body;
    db.run("DELETE FROM contacts WHERE id = ? AND user_id = ?", 
        [id, req.session.userId], 
        (err) => res.json(err ? { error: err.message } : { status: 'Eliminado' }));
});

app.post('/clear-contacts', auth, (req, res) => {
    db.run("DELETE FROM contacts WHERE user_id = ?", [req.session.userId], 
        (err) => res.json(err ? { error: err.message } : { status: 'Limpiado' }));
});

// Importar contactos desde Excel/CSV
app.post('/import-contacts', auth, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "Falta archivo" });

    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const sheetName = workbook.SheetNames[0];
        const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName], { header: 1 });

        let count = 0;
        const userId = req.session.userId;

        db.serialize(() => {
            const stmt = db.prepare("INSERT OR IGNORE INTO contacts (user_id, phone, name) VALUES (?, ?, ?)");
            data.forEach(row => {
                if (row[0]) {
                    let cleanPhone = String(row[0]).replace(/\D/g, '');
                    let name = row[1] ? String(row[1]) : "Cliente"; 
                    
                    if (cleanPhone.length > 6) {
                        stmt.run(userId, cleanPhone, name);
                        count++;
                    }
                }
            });
            stmt.finalize();
        });
        res.json({ msg: `✅ ${count} números importados.` });
    } catch (e) { res.status(500).json({ error: "Error en archivo" }); }
});

app.get('/my-contacts', auth, (req, res) => {
    db.all("SELECT * FROM contacts WHERE user_id = ?", [req.session.userId], (err, rows) => res.json(rows || []));
});

// --- Envío masivo ---
app.post('/send-campaign', auth, (req, res) => {
    const { message } = req.body;
    const { userId, username } = req.session;

    if (!client.info) return res.status(400).json({ msg: "❌ WhatsApp desconectado." });

    db.all("SELECT * FROM contacts WHERE user_id = ?", [userId], async (err, rows) => {
        if(!rows || rows.length === 0) return res.json({ msg: "Agenda vacía." });

        res.json({ msg: `🚀 Enviando a ${rows.length} contactos...` });

        for(const row of rows) {
            try {
                const chatId = `${row.phone}@c.us`;
                const finalMsg = message.replace('{name}', row.name);
                
                await client.sendMessage(chatId, finalMsg);
                
                db.run("INSERT INTO logs (user_id, username, type, message) VALUES (?, ?, ?, ?)",
                    [userId, username, 'ENVIO', `A: ${row.phone}`]);

                io.emit('log', { msg: `✅ Enviado a ${row.phone}` });
                await new Promise(r => setTimeout(r, Math.floor(Math.random() * 3000) + 4000));

            } catch(e) {
                console.error(e);
                io.emit('log', { msg: `❌ Error con ${row.phone}` });
            }
        }
    });
});

// --- Administración ---
app.post('/admin/create-user', auth, (req, res) => {
    if(req.session.role !== 'admin') return res.status(403).json({ error: "Acceso Denegado" });
    const hash = bcrypt.hashSync(req.body.password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [req.body.username, hash], 
        (err) => res.json(err ? { error: "Usuario existe" } : { status: "Creado" }));
});

app.get('/admin/export-logs', auth, (req, res) => {
    if(req.session.role !== 'admin') return res.status(403).json({ error: "Acceso Denegado" });
    const { start, end } = req.query;
    db.all(`SELECT timestamp, username, type, message FROM logs WHERE date(timestamp) BETWEEN ? AND ? ORDER BY timestamp DESC`, 
        [start, end], (err, rows) => res.json(rows));
});

// --- Inicio del servidor ---
server.listen(PORT, () => console.log(`🔥 SISTEMA V2.0 LISTO EN PUERTO ${PORT}`));

