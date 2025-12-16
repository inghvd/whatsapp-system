// --- 0) Variables de entorno ---
require('dotenv').config(); // ✅ Carga .env en local

// --- 1) Dependencias principales ---
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, LocalAuth } = require('whatsapp-web.js');
const QRCode = require('qrcode');
const session = require('express-session');
const MongoStore = require('connect-mongo'); // ✅ Store persistente v4
const bcrypt = require('bcryptjs');
const multer = require('multer');
const xlsx = require('xlsx');
const mongoose = require('mongoose');
const path = require('path'); // ← Agregado para rutas estáticas

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
app.use(express.static(path.join(__dirname, 'public'))); // ← Mejorado con path

// --- 9) Sesiones con MongoStore v4 ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'secreto_empresa_2025',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.DB_URL,
    ttl: 24 * 60 * 60, // 1 día
    collectionName: 'sessions'
  }),
  cookie: {
    maxAge: 3600000, // 1 hora
    secure: false // Render maneja TLS
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
  req.session.destroy(() => res.json({ status: 'ok' }));
});

const auth = (req, res, next) =>
  !req.session.userId ? res.status(403).json({ error: 'Sesión expirada' }) : next();

// --- 12) CRUD de Contactos (agentes) ---
// ... (todas tus rutas de contactos quedan igual: add-contact, my-contacts, etc.)
// (No las repito aquí para no alargar, pero déjalas exactamente como las tenías)

// --- NUEVAS RUTAS PARA EL PANEL ADMIN ---
const adminAuth = (req, res, next) => {
  if (!req.session.userId || req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado: solo admin' });
  }
  next();
};

// Crear nuevo usuario agente
app.post('/admin/create-user', adminAuth, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Faltan datos' });
    }
    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(400).json({ error: 'Usuario ya existe' });
    }
    const hash = bcrypt.hashSync(password, 10);
    await User.create({ username, password: hash, role: 'agent' });

    await Log.create({
      username: req.session.username,
      type: 'admin',
      message: `Creó usuario agente: ${username}`
    });

    res.json({ success: true, msg: 'Usuario creado correctamente' });
  } catch (e) {
    console.error('❌ Error /admin/create-user:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar todos los usuarios (solo agentes + admin)
app.get('/admin/get-users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, 'username role -_id');
    res.json(users);
  } catch (e) {
    console.error('❌ Error /admin/get-users:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Eliminar usuario agente
app.post('/admin/delete-user', adminAuth, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username || username === 'admin') {
      return res.status(400).json({ error: 'No puedes eliminar al admin principal' });
    }
    const result = await User.deleteOne({ username, role: 'agent' });
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    await Log.create({
      username: req.session.username,
      type: 'admin',
      message: `Eliminó usuario agente: ${username}`
    });

    res.json({ success: true, msg: 'Usuario eliminado' });
  } catch (e) {
    console.error('❌ Error /admin/delete-user:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// --- 13) Endpoints de depuración (mantén los que tenías) ---
// ... (debug/users, debug/contacts, etc.)

// --- 14) Salud del servicio ---
app.get('/health', (req, res) => {
  res.json({ status: 'ok', mongo: mongoose.connection.readyState });
});

// --- 15) Arranque del servidor ---
server.listen(PORT, () => {
  console.log(`🔥 SISTEMA V2.0 LISTO EN PUERTO ${PORT}`);
});
