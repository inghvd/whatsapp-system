// --- 0) Variables de entorno ---
require('dotenv').config();

// --- 1) Dependencias principales ---
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, LocalAuth } = require('whatsapp-web.js');
const QRCode = require('qrcode');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const xlsx = require('xlsx');
const mongoose = require('mongoose');
const path = require('path');

// --- 2) Inicialización ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3034;

// --- 4) Conexión MongoDB ---
if (!process.env.DB_URL) {
  console.error('❌ Falta DB_URL');
  process.exit(1);
}

mongoose.connect(process.env.DB_URL)
  .then(() => console.log('💾 MongoDB Atlas Conectado'))
  .catch(err => {
    console.error('❌ Error MongoDB:', err);
    process.exit(1);
  });

// --- 5) Modelos ---
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true, index: true },
  password: { type: String, required: true },
  role: { type: String, default: 'agent', enum: ['agent', 'admin'] }
});

const contactSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  phone: { type: String, required: true, index: true },
  name: { type: String, default: 'Cliente' }
});
contactSchema.index({ userId: 1, phone: 1 }, { unique: true });

const logSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  username: { type: String, required: true },
  type: { type: String, default: 'general' },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now, index: true }
});
logSchema.index({ timestamp: -1 });

const User = mongoose.model('User', userSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Log = mongoose.model('Log', logSchema);

// --- 6) Admin inicial ---
(async () => {
  try {
    const admin = await User.findOne({ username: 'admin' });
    if (!admin) {
      const hash = bcrypt.hashSync('1234', 10);
      await User.create({ username: 'admin', password: hash, role: 'admin' });
      console.log('👤 Admin inicial creado (cambia contraseña pronto)');
    }
  } catch (e) {
    console.error('Error creando admin:', e);
  }
})();

// --- 7) Multer ---
const upload = multer({ storage: multer.memoryStorage() });

// --- 8) Middlewares ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- 9) Sesiones ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'secreto_empresa_2025',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.DB_URL,
    ttl: 24 * 60 * 60,
    collectionName: 'sessions'
  }),
  cookie: { maxAge: 3600000, secure: false }
}));
console.log('🔐 SessionStore configurado');

// --- 10) WhatsApp Client ---
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

// --- 11) Login/Logout ---
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
    console.error('Error login:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ status: 'ok' }));
});

const auth = (req, res, next) => !req.session.userId ? res.status(403).json({ error: 'Sesión expirada' }) : next();
const adminAuth = (req, res, next) => {
  if (!req.session.userId || req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Solo admin' });
  }
  next();
};

// --- 12) RUTAS ADMIN (CORREGIDAS Y COMPLETAS) ---
app.post('/admin/create-user', adminAuth, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
    if (await User.findOne({ username })) return res.status(400).json({ error: 'Usuario ya existe' });

    const hash = bcrypt.hashSync(password, 10);
    await User.create({ username, password: hash, role: 'agent' });

    await Log.create({
      username: req.session.username,
      type: 'admin',
      message: `Creó usuario agente: ${username}`
    });

    res.json({ success: true, message: 'Usuario creado correctamente' });
  } catch (e) {
    console.error('Error create-user:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/admin/get-users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, 'username role -_id');
    res.json({ success: true, users });
  } catch (e) {
    res.status(500).json({ error: 'Error' });
  }
});

app.post('/admin/delete-user', adminAuth, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username || username === 'admin') return res.status(400).json({ error: 'No permitido' });

    const result = await User.deleteOne({ username, role: 'agent' });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrado' });

    await Log.create({
      username: req.session.username,
      type: 'admin',
      message: `Eliminó usuario: ${username}`
    });

    res.json({ success: true, message: 'Usuario eliminado' });
  } catch (e) {
    res.status(500).json({ error: 'Error' });
  }
});

// --- REPORTE CORREGIDO (zona horaria local) ---
app.get('/admin/export-logs', adminAuth, async (req, res) => {
  try {
    const { start, end } = req.query;
    let query = {};

    if (start && end) {
      const startDate = new Date(start);
      startDate.setHours(0, 0, 0, 0);

      const endDate = new Date(end);
      endDate.setHours(23, 59, 59, 999);

      query.timestamp = { $gte: startDate, $lte: endDate };
    }

    const logs = await Log.find(query).sort({ timestamp: -1 }).lean();
    res.json(logs);
  } catch (e) {
    console.error('Error export-logs:', e);
    res.status(500).json([]);
  }
});

// --- 14) Health ---
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// --- 15) Listen ---
server.listen(PORT, () => {
  console.log(`🔥 SISTEMA LISTO EN PUERTO ${PORT}`);
});
