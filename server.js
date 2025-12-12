// --- Dependencias principales ---
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, LocalAuth } = require('whatsapp-web.js');
const QRCode = require('qrcode');
const session = require('express-session');
const MongoStore = require('connect-mongo');   // 🔧 Store persistente
const bcrypt = require('bcryptjs');
const multer = require('multer');
const xlsx = require('xlsx');
const mongoose = require('mongoose');

// --- Inicialización de servidor ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// 🔧 Puerto dinámico para Render, fijo 3034 en local
const PORT = process.env.PORT || 3034;

// --- Conexión a MongoDB Atlas ---
if (!process.env.DB_URL) {
  console.error('❌ Falta la variable DB_URL');
  process.exit(1);
}
mongoose.connect(process.env.DB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('💾 MongoDB Atlas Conectado'))
  .catch(err => {
    console.error('❌ Error MongoDB:', err);
    process.exit(1);
  });

// --- Modelos (Mongoose) ---
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

// --- Semilla de admin por defecto ---
(async () => {
  const admin = await User.findOne({ username: 'admin' });
  if (!admin) {
    const hash = bcrypt.hashSync('1234', 10);
    await User.create({ username: 'admin', password: hash, role: 'admin' });
    console.log('👤 Usuario admin inicial creado');
  }
})();

// --- Configuración de subida de archivos ---
const upload = multer({ storage: multer.memoryStorage() });

// --- Middlewares ---
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secreto_empresa_2025',
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({       // 🔧 CORREGIDO: usar constructor
    mongoUrl: process.env.DB_URL,
    ttl: 24 * 60 * 60
  }),
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

// --- Autenticación ---
app.post('/login', async (req, res) => {
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
});
app.post('/logout', (req, res) => req.session.destroy(() => res.json({ status: 'ok' })));
const auth = (req, res, next) => !req.session.userId ? res.status(403).json({ error: 'Sesión expirada' }) : next();

// --- CRUD de Contactos ---
app.post('/add-contact', auth, async (req, res) => {
  try {
    const { name, phone } = req.body || {};
    const cleanPhone = String(phone).replace(/\D/g, '');
    await Contact.create({ userId: req.session.userId, phone: cleanPhone, name: name || 'Cliente' });
    res.json({ status: 'Guardado' });
  } catch (err) {
    if (err.code === 11000) return res.json({ error: 'Contacto ya existe' });
    res.status(500).json({ error: 'Error interno' });
  }
});
app.get('/my-contacts', auth, async (req, res) => {
  const rows = await Contact.find({ userId: req.session.userId }).sort({ name: 1 });
  res.json(rows || []);
});

// --- Envío masivo ---
app.post('/send-campaign', auth, async (req, res) => {
  const { message } = req.body || {};
  const { userId, username } = req.session;
  if (!message) return res.status(400).json({ msg: 'Falta mensaje' });
  if (!client.info) return res.status(400).json({ msg: '❌ WhatsApp desconectado.' });
  const contacts = await Contact.find({ userId });
  if (!contacts.length) return res.json({ msg: 'Agenda vacía.' });
  res.json({ msg: `🚀 Enviando a ${contacts.length} contactos...` });
  for (const row of contacts) {
    try {
      const chatId = `${row.phone}@c.us`;
      const finalMsg = message.replace('{name}', row.name || 'Cliente');
      await client.sendMessage(chatId, finalMsg);
      await Log.create({ userId, username, type: 'ENVIO', message: `A: ${row.phone}` });
      io.emit('log', { msg: `✅ Enviado a ${row.phone}` });
      await new Promise(r => setTimeout(r, Math.floor(Math.random() * 3000) + 4000));
    } catch (e) {
      io.emit('log', { msg: `❌ Error con ${row.phone}` });
    }
  }
});

// --- Administración ---
app.post('/admin/create-user', auth, async (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Acceso Denegado' });
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
  if (await User.findOne({ username })) return res.json({ error: 'Usuario existe' });
  const hash = bcrypt.hashSync(password, 10);
  await User.create({ username, password: hash, role: role || 'agent' });
  res.json({ status: 'Creado' });
});

// --- Inicio del servidor ---
server.listen(PORT, () => console.log(`🔥 SISTEMA V2.0 LISTO EN PUERTO ${PORT}`));

