const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// KONFIGURASI MULTER UNTUK UPLOAD FOTO (Aman untuk Laptop & Vercel)
const uploadDir = process.env.VERCEL ? '/tmp' : path.join(__dirname, 'public/uploads');
// KONFIGURASI MULTER KE MEMORI (AMAN UNTUK VERCEL)
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // Maksimal 2MB agar database tetap ringan
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Format foto harus JPG, JPEG, PNG, atau WEBP'));
        }
    }
});

// 1. SETUP SESSION UNTUK PENGAMANAN LOGIN
app.use(session({
    secret: 'unpam_parking_secret_key',
    resave: false,
    saveUninitialized: true
}));

// 2. SETUP POOL KONEKSI DATABASE MYSQL XAMPP
// 1. Pastikan SSL mendukung TLSv1.2 untuk TiDB Cloud
const dbPool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'unpam_parking',
    ssl: process.env.DB_HOST ? { minVersion: 'TLSv1.2', rejectUnauthorized: true } : null
});

// Middleware untuk memproteksi halaman (wajib login)
function checkLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login-mahasiswa');
    }
    next();
}

// --- ROUTES AUTENTIKASI ---

app.get('/login-mahasiswa', (req, res) => res.render('login-mahasiswa'));
app.get('/login-petugas', (req, res) => res.render('login-petugas'));
app.get('/register-mahasiswa', (req, res) => res.render('register-mahasiswa'));

// Proses Registrasi Mandiri Mahasiswa (Pake NIM)
app.post('/register-mahasiswa', async (req, res) => {
    try {
        const { nim, nama_lengkap, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const sql = 'INSERT INTO users_mahasiswa (nim, nama_lengkap, password) VALUES (?, ?, ?)';
        await dbPool.query(sql, [nim, nama_lengkap, hashedPassword]);
        res.redirect('/login-mahasiswa');
    } catch (error) {
        res.render('register-mahasiswa', { error: 'NIM sudah terdaftar / Data Gagal Disimpan!' });
    }
});

// Proses Login Mahasiswa
app.post('/login-mahasiswa', async (req, res) => {
    const { nim, password } = req.body;
    try {
        const [rows] = await dbPool.query('SELECT * FROM users_mahasiswa WHERE nim = ?', [nim]);
        if (rows.length > 0) {
            const match = await bcrypt.compare(password, rows[0].password);
            if (match) {
                req.session.user = { role: 'mahasiswa', id: rows[0].id, nama: rows[0].nama_lengkap };
                return res.redirect('/');
            }
        }
        res.render('login-mahasiswa', { error: 'NIM atau Password salah!' });
    } catch (error) {
        res.status(500).send("Eror sistem login");
    }
});

// Proses Login Petugas
app.post('/login-petugas', async (req, res) => {
    const { username_petugas, password } = req.body;
    try {
        const [rows] = await dbPool.query('SELECT * FROM users_petugas WHERE username_petugas = ?', [username_petugas]);
        if (rows.length > 0 && rows[0].password === password) {
            req.session.user = { role: 'petugas', id: rows[0].id, nama: rows[0].nama_petugas };
            return res.redirect('/');
        }
        res.render('login-petugas', { error: 'Username Petugas atau Password salah!' });
   } catch (error) {
    res.status(500).send("Eror sistem login: " + error.message);
}

});

// Proses Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login-mahasiswa');
});


// --- ROUTES UTAMA DASHBOARD CRUD (TERPROTEKSI) ---

// 1. READ: Tampilkan Dashboard Utama
app.get('/', checkLogin, async (req, res) => {
    try {
        const [rowsParkir] = await dbPool.query(`
            SELECT sp.*, up.nama_petugas, up.shift 
            FROM status_parkir sp 
            LEFT JOIN users_petugas up ON sp.id_petugas = up.id
        `);
        
        const [rowsLaporan] = await dbPool.query(`
            SELECT lm.*, um.nim, um.nama_lengkap 
            FROM laporan_mahasiswa lm 
            LEFT JOIN users_mahasiswa um ON lm.id_mahasiswa = um.id
            ORDER BY lm.id DESC
        `);

        res.render('index', { 
            user: req.session.user,
            dataParkirLantai: rowsParkir,
            dataLaporanMahasiswa: rowsLaporan
        });
    } catch (error) {
        res.status(500).send("Gagal memuat dashboard");
    }
});

// 2. CREATE: Mahasiswa Mengirim Pengaduan Baru + Upload Foto
app.post('/laporan-mahasiswa', checkLogin, upload.single('foto'), async (req, res) => {
    if (req.session.user.role !== 'mahasiswa') return res.status(403).send("Akses Ditolak!");
    
    try {
        const { kategori, judul, is_anonim, deskripsi } = req.body;
        const id_mahasiswa = req.session.user.id;
        const foto = req.file ? `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}` : null;
        
        const sql = 'INSERT INTO laporan_mahasiswa (kategori, judul, is_anonim, deskripsi, id_mahasiswa, foto) VALUES (?, ?, ?, ?, ?, ?)';
        await dbPool.query(sql, [kategori, judul, parseInt(is_anonim), deskripsi, id_mahasiswa, foto]);
        res.redirect('/');
    } catch (error) {
        res.status(500).send("Gagal mengirim laporan");
    }
});

// 3A. UPDATE (MAHASISWA): Memproses Edit Kendala dari Pop-Up Modal + Ganti Foto
app.post('/laporan-mahasiswa/update/:id', checkLogin, upload.single('foto'), async (req, res) => {
    try {
        const id = req.params.id;
        const { kategori, judul, is_anonim, deskripsi } = req.body;
        
        const [rows] = await dbPool.query('SELECT * FROM laporan_mahasiswa WHERE id = ?', [id]);
        if (rows.length === 0) return res.status(404).send("Laporan tidak ditemukan");

        if (req.session.user.role === 'mahasiswa' && req.session.user.id === rows[0].id_mahasiswa) {
            const foto = req.file ? `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}` : rows[0].foto;
            const sql = 'UPDATE laporan_mahasiswa SET kategori = ?, judul = ?, is_anonim = ?, deskripsi = ?, foto = ? WHERE id = ?';
            await dbPool.query(sql, [kategori, judul, parseInt(is_anonim), deskripsi, foto, id]);
            return res.redirect('/');
        }
        res.status(403).send("Anda tidak memiliki hak mengedit laporan ini!");
    } catch (error) {
        res.status(500).send("Gagal memperbarui laporan");
    }
});

// 3B. UPDATE (PETUGAS): Memproses Perubahan Status Kapasitas + Upload Foto Kondisi Lantai
app.post('/parkir/update/:id', checkLogin, upload.single('foto'), async (req, res) => {
    if (req.session.user.role !== 'petugas') return res.status(403).send("Akses Ditolak!");
    
    try {
        const id = req.params.id;
        const { status, keterangan } = req.body;
        const id_petugas = req.session.user.id;

        const [rows] = await dbPool.query(
            'SELECT foto FROM status_parkir WHERE id = ?',
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).send("Data parkir tidak ditemukan");
        }

        const foto = req.file ? `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}` : rows[0].foto;

        const sql = 'UPDATE status_parkir SET status = ?, keterangan = ?, id_petugas = ?, foto = ? WHERE id = ?';
        await dbPool.query(sql, [status, keterangan, id_petugas, foto, id]);
        res.redirect('/');
    } catch (error) {
        res.status(500).send("Gagal memperbarui status");
    }
});

// 4. DELETE: Hapus Pengaduan Mahasiswa
app.post('/laporan-mahasiswa/delete/:id', checkLogin, async (req, res) => {
    try {
        const id = req.params.id;
        const [rows] = await dbPool.query('SELECT id_mahasiswa FROM laporan_mahasiswa WHERE id = ?', [id]);
        
        if (rows.length > 0) {
            const pemilikAsliId = rows[0].id_mahasiswa;
            if (req.session.user.role === 'petugas' || (req.session.user.role === 'mahasiswa' && req.session.user.id === pemilikAsliId)) {
                await dbPool.query('DELETE FROM laporan_mahasiswa WHERE id = ?', [id]);
                return res.redirect('/');
            }
        }
        res.status(403).send("Anda tidak memiliki hak menghapus laporan ini!");
    } catch (error) {
        res.status(500).send("Gagal memproses penghapusan");
    }
});

app.listen(PORT, () => console.log(`Server Real-Time UNPAM Parking Aktif di http://localhost:${PORT}`));
module.exports = app;