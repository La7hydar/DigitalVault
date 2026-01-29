const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // Wajib ada untuk baca file HTML

const app = express();
const PORT = 3000;
const SECRET_KEY = 'rahasia_negara_digitalvault';

// --- 1. SETTING WAJIB (Agar HTML & API Jalan Bareng) ---
app.use(cors());
app.use(express.json());

// PENTING: Baris ini membuat server bisa membuka file index.html, shop.html, dll
app.use(express.static(__dirname)); 

// --- 2. KONEKSI DATABASE ---
mongoose.connect('mongodb://127.0.0.1:27017/digitalvault_db')
.then(() => console.log('✅ DATABASE TERHUBUNG'))
.catch(err => console.error('❌ Gagal koneksi DB:', err));

// --- 3. SKEMA DATA ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

const OrderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String, notes: String, qty: Number, time: String,
    status: { type: String, default: 'Diproses' },
    date: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);

// --- 4. RUTE HALAMAN (Website) ---
// Kalau buka http://localhost:3000/ langsung buka index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- 5. RUTE API (Backend) ---

// REGISTER
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const existing = await User.findOne({ username });
        if(existing) return res.status(400).json({ message: "Username sudah dipakai!" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: "Registrasi Berhasil!" });
    } catch (err) { res.status(500).json({ message: "Server Error" }); }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if(!user) return res.status(400).json({ message: "Username tidak ditemukan!" });

        const validPass = await bcrypt.compare(password, user.password);
        if(!validPass) return res.status(400).json({ message: "Password salah!" });

        const token = jwt.sign({ id: user._id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ message: "Login Berhasil", token, user: { username: user.username } });
    } catch (err) { res.status(500).json({ message: "Server Error" }); }
});

// Middleware Cek Token
const verifyToken = (req, res, next) => {
    const header = req.headers['authorization'];
    if(!header) return res.status(401).json({ message: "Akses Ditolak" });
    const token = header.split(' ')[1];
    if(!token) return res.status(401).json({ message: "Token Invalid" });
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if(err) return res.status(401).json({ message: "Sesi Habis" });
        req.user = decoded;
        next();
    });
};

// API Order (CRUD)
app.post('/api/orders', verifyToken, async (req, res) => {
    try {
        const newOrder = new Order({ ...req.body, userId: req.user.id });
        await newOrder.save();
        res.status(201).json(newOrder);
    } catch (err) { res.status(500).json({ message: "Gagal Simpan" }); }
});

app.get('/api/orders', verifyToken, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.user.id }).sort({ date: -1 });
        res.json(orders);
    } catch (err) { res.status(500).json({ message: "Gagal Ambil Data" }); }
});

app.delete('/api/orders/:id', verifyToken, async (req, res) => {
    try {
        await Order.findByIdAndDelete(req.params.id);
        res.json({ message: "Terhapus" });
    } catch (err) { res.status(500).json({ message: "Gagal Hapus" }); }
});

app.delete('/api/orders', verifyToken, async (req, res) => {
    try {
        await Order.deleteMany({ userId: req.user.id });
        res.json({ message: "Bersih" });
    } catch (err) { res.status(500).json({ message: "Gagal Bersihkan" }); }
});

// --- 6. JALANKAN SERVER ---
app.listen(PORT, () => {
    console.log(`🚀 WEBSITE SIAP: http://localhost:${PORT}`);
});