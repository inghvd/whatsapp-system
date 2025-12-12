// --- Dependencias principales ---
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
mongoose
  .connect(process.env.DB_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('💾 MongoDB Atlas Conectado'))
  .catch((err) => {
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

// --- Semilla de admin por defecto (admin/1234) ---
(async () => {
  const admin = await User.findOne({ username: 'admin' });
  if (!admin) {
    const hash = bcrypt.hashSync('1234', 10);
    await User.create({ username: 'admin', password: hash, role: 'admin' });
    console.log('👤 Usuario admin inicial creado');
  }
})();

// --- Configuración de subida de archivos en memoria ---
const upload = multer({ storage: multer.memoryStorage() });

// --- Middlewares ---
app.use(express.json());
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'secreto_empresa_2025',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.DB_URL,
      ttl: 24 * 60 * 60 // 1 día
    }),
    cookie: { maxAge: 3600000 } // 1 hora
  })
);

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
  QRCode.toDataURL(qr, (err, url) => {
    if (err) {
      console.error('❌ Error QR:', err);
      return;
    }
    io.emit('qr', { src: url });
  });
});

// Conexión lista
client.on('ready', () => {
  console.log('✅ WHATSAPP CONECTADO');
  io.emit('ready', { status: 'Conectado' });
});

client.initialize();

// --- Autenticación ---
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
  } catch (err) {
    console.error('❌ /login:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ status: 'ok' }));
});

// Middleware de auth
const auth = (req, res, next) => {
  if (!req.session.userId) return res.status(403).json({ error: 'Sesión expirada' });
  next();
};

// --- CRUD de Contactos ---
app.post('/add-contact', auth, async (req, res) => {
  try {
    const { name, phone } = req.body || {};
    if (!phone) return res.status(400).json({ error: 'Falta teléfono' });

    const cleanPhone = String(phone).replace(/\D/g, '');
    await Contact.create({ userId: req.session.userId, phone: cleanPhone, name: name || 'Cliente' });

    res.json({ status: 'Guardado' });
  } catch (err) {
    // Duplicate key error
    if (err && err.code === 11000) return res.json({ error: 'Contacto ya existe' });
    console.error('❌ /add-contact:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/update-contact', auth, async (req, res) => {
  try {
    const { id, name, phone } = req.body || {};
    if (!id) return res.status(400).json({ error: 'Falta id' });

    const cleanPhone = phone ? String(phone).replace(/\D/g, '') : undefined;
    const updated = await Contact.updateOne(
      { _id: id, userId: req.session.userId },
      { $set: { ...(name ? { name } : {}), ...(cleanPhone ? { phone: cleanPhone } : {}) } }
    );

    if (updated.matchedCount === 0) return res.json({ error: 'No encontrado' });
    res.json({ status: 'Actualizado' });
  } catch (err) {
    if (err && err.code === 11000) return res.json({ error: 'Número duplicado' });
    console.error('❌ /update-contact:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/delete-contact', auth, async (req, res) => {
  try {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ error: 'Falta id' });

    await Contact.deleteOne({ _id: id, userId: req.session.userId });
    res.json({ status: 'Eliminado' });
  } catch (err) {
    console.error('❌ /delete-contact:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/clear-contacts', auth, async (req, res) => {
  try {
    await Contact.deleteMany({ userId: req.session.userId });
    res.json({ status: 'Limpiado' });
  } catch (err) {
    console.error('❌ /clear-contacts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Importar contactos desde Excel/CSV
app.post('/import-contacts', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Falta archivo' });

  try {
    const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName], { header: 1 });

    let count = 0;
    const bulkOps = [];
    const userId = req.session.userId;

    data.forEach((row) => {
      if (row && row[0]) {
        const cleanPhone = String(row[0]).replace(/\D/g, '');
        const name = row[1] ? String(row[1]) : 'Cliente';
        if (cleanPhone.length > 6) {
          bulkOps.push({
            updateOne: {
              filter: { userId, phone: cleanPhone },
              update: { $setOnInsert: { userId, phone: cleanPhone, name } },
              upsert: true
            }
          });
        }
      }
    });

    if (bulkOps.length > 0) {
      const result = await Contact.bulkWrite(bulkOps, { ordered: false });
      count = (result.upsertedCount || 0) + (result.modifiedCount || 0);
    }

    res.json({ msg: `✅ ${count} números importados.` });
  } catch (e) {
    console.error('❌ /import-contacts:', e);
    res.status(500).json({ error: 'Error en archivo' });
  }
});

app.get('/my-contacts', auth, async (req, res) => {
  try {
    const rows = await Contact.find({ userId: req.session.userId }).sort({ name: 1, phone: 1 });
    res.json(rows || []);
  } catch (err) {
    console.error('❌ /my-contacts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// --- Envío masivo ---
app.post('/send-campaign', auth, async (req, res) => {
  const { message } = req.body || {};
  const { userId, username } = req.session;

  if (!message) return res.status(400).json({ msg: 'Falta mensaje' });
  if (!client.info) return res.status(400).json({ msg: '❌ WhatsApp desconectado.' });

  try {
    const contacts = await Contact.find({ userId });
    if (!contacts || contacts.length === 0) return res.json({ msg: 'Agenda vacía.' });

    res.json({ msg: `🚀 Enviando a ${contacts.length} contactos...` });

    for (const row of contacts) {
      try {
        const chatId = `${row.phone}@c.us`;
        const finalMsg = message.replace('{name}', row.name || 'Cliente');

        await client.sendMessage(chatId, finalMsg);

        await Log.create({
          userId,
          username,
          type: 'ENVIO',
          message: `A: ${row.phone}`
        });

        io.emit('log', { msg: `✅ Enviado a ${row.phone}` });
        await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 3000) + 4000));
      } catch (e) {
        console.error('❌ Envío:', e);
        io.emit('log', { msg: `❌ Error con ${row.phone}` });
      }
    }
  } catch (err) {
    console.error('❌ /send-campaign:', err);
  }
});

// --- Administración ---
app.post('/admin/create-user', auth, async (req, res) => {
  try {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Acceso Denegado' });
    const { username, password, role } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

    const exists = await User.findOne({ username });
    if (exists) return res.json({ error: 'Usuario existe' });

    const hash = bcrypt.hashSync(password, 10);
    await User.create({ username, password: hash, role: role || 'agent' });
    res.json({ status: 'Creado' });
  } catch (err) {
    console.error('❌ /admin/create-user:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/admin/export-logs', auth, async (req, res) => {
  try {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Acceso Denegado' });
    const { start, end } = req.query || {};
    const startDate = start ? new Date(start) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // 7 días
    const endDate = end ? new Date(end) : new Date();

    const rows = await Log.find({
      timestamp: { $gte: startDate, $lte: endDate }
    }).sort({ timestamp: -1 });

    res.json(rows || []);
  } catch (err) {
    console.error('❌ /admin/export-logs:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// --- Inicio del servidor ---
server.listen(PORT, () => console.log(`🔥 SISTEMA V2.0 LISTO EN PUERTO ${PORT}`));

