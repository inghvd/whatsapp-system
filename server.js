// --- 0) Variables de entorno ---
require('dotenv').config(); // ✅ Carga .env en local

// --- 1) Dependencias principales ---
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, LocalAuth } = require('whatsapp-web.js');
const QRCode = require('qrcode');
const session = require('express-session');
const MongoStore = require('connect-mongo');   // ✅ Store persistente v4
const bcrypt = require('bcryptjs');
const multer = require('multer');
const xlsx = require('xlsx');
const mongoose = require('mongoose');

// --- 2) Inicialización de servidor y sockets ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- 3) Puerto dinámico (Render) o 3034 local ---
const PORT = process.env.PORT || 3034;

// --- 4) Validación y conexión a MongoDB Atlas ---
if (!process.env.DB_URL) {
  console.error('❌ Falta la variable DB_URL');
  process.exit(1);
}
mongoose.connect(process.env.DB_URL)
  .then(() => console.log('💾 MongoDB Atlas Conectado'))
  .catch(err => {
    console.error('❌ Error MongoDB:', err);
    process.exit(1);
  });

// --- 5) Modelos (Mongoose) ---
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, index: true },
  password: String,
  role: { type: String, default: 'agent' }
});
const contactSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  phone: { type: String, index: true },
  name: String
});
contactSchema.index({ userId: 1, phone: 1 }, { unique: true });
const logSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  username: String,
  type: String,
  message: String,
  timestamp: { type: Date, default: Date.now, index: true }
});
const User = mongoose.model('User', userSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Log = mongoose.model('Log', logSchema);

// --- 6) Semilla de admin por defecto ---
(async () => {
  try {
    const admin = await User.findOne({ username: 'admin' });
    if (!admin) {
      const hash = bcrypt.hashSync('1234', 10);
      await User.create({ username: 'admin', password: hash, role: 'admin' });
      console.log('👤 Usuario admin inicial creado');
    }
  } catch (e) {
    console.error('❌ Error creando admin inicial:', e);
  }
})();

// --- 7) Configuración de subida de archivos ---
const upload = multer({ storage: multer.memoryStorage() });

// --- 8) Middlewares generales ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- 9) Sesiones con MongoStore v4 ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'secreto_empresa_2025',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.DB_URL,
    ttl: 24 * 60 * 60,
    collectionName: 'sessions'
  }),
  cookie: {
    maxAge: 3600000, // 1 hora
    secure: false    // Render maneja TLS, false funciona bien
  }
}));
console.log('🔐 SessionStore: MongoStore v4 configurado');

// --- 10) Cliente WhatsApp y eventos ---
const client = new Client({
  authStrategy: new LocalAuth(),
  puppeteer: {
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
  }
});

client.on('qr', (qr) => {
  console.log('📲 QR GENERADO');
  QRCode.toDataURL(qr, (err, url) => {
    if (!err) io.emit('qr', { src: url });
  });
});

client.on('ready', () => {
  console.log('✅ WHATSAPP CONECTADO');
  io.emit('ready', { status: 'Conectado' });
});

client.initialize();

// --- 11) Autenticación y sesión ---
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });
    const user = await User.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Datos incorrectos' });
    }
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.role = user.role;
    res.json({ role: user.role, username: user.username });
  } catch (e) {
    console.error('❌ Error /login:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/logout', (req, res) => {
  try {
    req.session.destroy(() => res.json({ status: 'ok' }));
  } catch (e) {
    res.json({ status: 'ok' });
  }
});

const auth = (req, res, next) =>
  !req.session.userId ? res.status(403).json({ error: 'Sesión expirada' }) : next();

// --- 12) CRUD de Contactos ---
app.post('/add-contact', auth, async (req, res) => {
  try {
    const { name, phone } = req.body || {};
    const cleanPhone = String(phone).replace(/\D/g, '');
    if (!cleanPhone) return res.status(400).json({ error: 'Teléfono inválido' });
    await Contact.create({
      userId: req.session.userId,
      phone: cleanPhone,
      name: (name || '').trim() || 'Cliente'
    });
    res.json({ status: 'Guardado' });
  } catch (err) {
    if (err.code === 11000) return res.json({ error: 'Contacto ya existe' });
    console.error('❌ Error add-contact:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/my-contacts', auth, async (req, res) => {
  try {
    const rows = await Contact.find({ userId: req.session.userId }).sort({ name: 1 });
    res.json(rows || []);
  } catch (e) {
    console.error('❌ Error my-contacts:', e);
    res.json([]);
  }
});

app.post('/update-contact', auth, async (req, res) => {
  try {
    const { id, name, phone } = req.body || {};
    if (!id) return res.status(400).json({ error: 'Falta id' });
    const cleanPhone = String(phone).replace(/\D/g, '');
    await Contact.updateOne(
      { _id: id, userId: req.session.userId },
      { $set: { name: (name || '').trim() || 'Cliente', phone: cleanPhone } }
    );
    res.json({ status: 'Actualizado' });
  } catch (e) {
    console.error('❌ Error update-contact:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/delete-contact', auth, async (req, res) => {
  try {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ error: 'Falta id' });
    await Contact.deleteOne({ _id: id, userId: req.session.userId });
    res.json({ status: 'Eliminado' });
  } catch (e) {
    console.error('❌ Error delete-contact:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/clear-contacts', auth, async (req, res) => {
  try {
    await Contact.deleteMany({ userId: req.session.userId });
    res.json({ status: 'Agenda vaciada' });
  } catch (e) {
    console.error('❌ Error clear-contacts:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/import-contacts', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Falta archivo' });
    const wb = xlsx.read(req.file.buffer, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows = xlsx.utils.sheet_to_json(sheet);
    let count = 0;
    for (const r of rows) {
      const name = (r.Nombre || r.name || '').trim();
      const phone = String(r
