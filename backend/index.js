const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = 5000;
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE']
  }
});

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

app.use(cors());
app.use(express.json({ limit: '20mb' }));

// Cloudinary konfigürasyonu - Unsigned upload için sadece cloud_name gerekli
cloudinary.config({
  cloud_name: 'ddkc67grz'
});

// Multer konfigürasyonu
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Product modeli
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  images: [{ type: String, required: false }],
  description: { type: String, required: true },
  stock: { type: Number, required: true },
  cutType: { type: String },
  productionPlace: { type: String },
  material: { type: String },
  modelHeight: { type: String },
  modelSize: { type: String },
  sizes: [{ type: String }], // Bedenler
  pattern: { type: String }, // Desen
  sustainability: { type: String }, // Sürdürülebilirlik Detayı
  sleeveType: { type: String }, // Kol Tipi
  collarType: { type: String }, // Yaka Tipi
  legLength: { type: String }, // Paça Boyu
  color: { type: String }, // Renk
  productType: { type: String }, // Ürün Tipi
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  createdAt: { type: Date, default: Date.now },
});
const Product = mongoose.model('Product', productSchema);

// Ürünleri listeleme endpoint'i
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Ürünler alınamadı' });
  }
});

// Tek ürün getirme endpoint'i
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Ürün bulunamadı' });
    }
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: 'Ürün alınamadı' });
  }
});

// Ürün ekleme endpoint'i
app.post('/api/products', async (req, res) => {
  try {
    const { name, price, stock, description, images, category } = req.body;
    
    console.log('Ürün ekleme - Gelen veri:', { name, price, stock, description, category });
    
    if (!name || !price || !stock || !description || !images || images.length === 0) {
      return res.status(400).json({ message: 'Tüm alanlar gereklidir ve en az bir resim gerekli' });
    }

    const product = new Product({
      name,
      price: Number(price),
      stock: Number(stock),
      description,
      images,
      category: category || null
    });

    console.log('Kaydedilecek ürün:', product);

    await product.save();
    console.log('Ürün kaydedildi:', product);
    
    io.emit('productsUpdated');
    res.status(201).json(product);
  } catch (error) {
    console.error('Ürün ekleme hatası:', error);
    res.status(500).json({ message: 'Ürün eklenirken hata oluştu' });
  }
});

// Ürün silme endpoint'i
app.delete('/api/products/:id', async (req, res) => {
  try {
    const deleted = await Product.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Ürün bulunamadı' });
    io.emit('productsUpdated');
    res.json(deleted);
  } catch (err) {
    res.status(500).json({ error: 'Ürün silinemedi' });
  }
});

// Ürün güncelleme endpoint'i
app.put('/api/products/:id', async (req, res) => {
  try {
    console.log('=== ÜRÜN GÜNCELLEME BAŞLADI ===');
    console.log('Request params:', req.params);
    console.log('Request body:', req.body);
    
    const { 
      name, 
      price, 
      stock, 
      description, 
      images, 
      category,
      cutType,
      productionPlace,
      material,
      modelHeight,
      modelSize,
      sizes,
      pattern,
      sustainability,
      sleeveType,
      collarType,
      legLength,
      color,
      productType
    } = req.body;
    const { id } = req.params;
    
    console.log('Çıkarılan veriler:', { 
      id, 
      name, 
      price, 
      stock, 
      description, 
      category,
      cutType,
      productionPlace,
      material,
      modelHeight,
      modelSize,
      sizes,
      pattern,
      sustainability,
      sleeveType,
      collarType,
      legLength,
      color,
      productType
    });
    
    if (!name || !price || !stock || !description || !images || images.length === 0) {
      console.log('Validasyon hatası - eksik alanlar');
      return res.status(400).json({ message: 'Tüm alanlar gereklidir ve en az bir resim gerekli' });
    }

    const updateData = {
      name,
      price: Number(price),
      stock: Number(stock),
      description,
      images,
      category: category || null,
      cutType: cutType || null,
      productionPlace: productionPlace || null,
      material: material || null,
      modelHeight: modelHeight || null,
      modelSize: modelSize || null,
      sizes: sizes || [],
      pattern: pattern || null,
      sustainability: sustainability || null,
      sleeveType: sleeveType || null,
      collarType: collarType || null,
      legLength: legLength || null,
      color: color || null,
      productType: productType || null
    };

    console.log('Güncellenecek veri:', updateData);
    console.log('MongoDB ID:', id);

    const product = await Product.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    );

    if (!product) {
      console.log('Ürün bulunamadı - ID:', id);
      return res.status(404).json({ message: 'Ürün bulunamadı' });
    }

    console.log('Güncellenmiş ürün:', product);
    console.log('=== ÜRÜN GÜNCELLEME BAŞARILI ===');
    
    io.emit('productsUpdated');
    res.json(product);
  } catch (error) {
    console.error('Ürün güncelleme hatası:', error);
    res.status(500).json({ message: 'Ürün güncellenirken hata oluştu: ' + error.message });
  }
});

// Order modeli
const orderSchema = new mongoose.Schema({
  products: [
    {
      _id: String,
      name: String,
      price: Number,
      qty: Number,
      image: String,
      selectedSize: String, // Seçilen beden
      cutType: String, // Kesim tipi
      productionPlace: String, // Üretim yeri
      material: String, // Materyal
      modelHeight: String, // Model boyu
      modelSize: String, // Model bedeni
      pattern: String, // Desen
      sustainability: String, // Sürdürülebilirlik
      sleeveType: String, // Kol tipi
      collarType: String, // Yaka tipi
      legLength: String, // Paça boyu
      color: String, // Renk
      productType: String, // Ürün tipi
      sizes: [String], // Mevcut bedenler
      stock: Number, // Stok bilgisi
      description: String // Ürün açıklaması
    }
  ],
  userEmail: String,
  address: {
    name: String,
    surname: String,
    phone: String,
    address: String,
    city: String,
    district: String,
    zip: String
  },
  total: Number,
  status: { type: String, default: 'Ödeme Bekleniyor' },
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// SupportTicket modeli (güncel)
const supportTicketSchema = new mongoose.Schema({
  orderId: String,
  userEmail: String,
  message: String, // ilk mesaj
  messages: [{ sender: String, message: String, date: { type: Date, default: Date.now } }],
  status: { type: String, default: 'Açık' },
  chatOpen: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Category Model
const categorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    unique: true
  },
  description: {
    type: String,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Category = mongoose.model('Category', categorySchema);

// MongoDB bağlantısı
mongoose.connect('mongodb://127.0.0.1:27017/sellweb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User modeli
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
});
const User = mongoose.model('User', userSchema);

// Kayıt endpointi
app.post('/api/register', async (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password || !username) return res.status(400).json({ error: 'Email, kullanıcı adı ve şifre zorunlu' });
  try {
    const existingEmail = await User.findOne({ email });
    if (existingEmail) return res.status(400).json({ error: 'Bu email zaten kayıtlı' });
    const existingUsername = await User.findOne({ username });
    if (existingUsername) return res.status(400).json({ error: 'Bu kullanıcı adı zaten alınmış' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, username, password: hashed });
    res.status(201).json({ message: 'Kayıt başarılı' });
  } catch (err) {
    res.status(500).json({ error: 'Kayıt sırasında hata oluştu' });
  }
});

// Giriş endpointi (email veya kullanıcı adı ile)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email/kullanıcı adı ve şifre zorunlu' });
  try {
    // email alanı hem e-posta hem kullanıcı adı olabilir
    const user = await User.findOne({ $or: [ { email }, { username: email } ] });
    if (!user) return res.status(400).json({ error: 'Kullanıcı bulunamadı' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Şifre hatalı' });
    const token = jwt.sign({ id: user._id, email: user.email, username: user.username, role: user.role }, 'SECRET_KEY', { expiresIn: '1d' });
    res.json({ token, user: { email: user.email, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Giriş sırasında hata oluştu' });
  }
});

// Sipariş oluşturma endpointi (demo)
app.post('/api/orders', async (req, res) => {
  const { cart, email, address } = req.body;
  if (!cart || !Array.isArray(cart) || cart.length === 0) {
    return res.status(400).json({ error: 'Sepet boş' });
  }
  try {
    // Stok kontrolü ve güncelleme
    for (const item of cart) {
      const product = await Product.findById(item._id);
      if (!product) {
        return res.status(400).json({ error: `Ürün bulunamadı: ${item.name}` });
      }
      if (product.stock < item.qty) {
        return res.status(400).json({ error: `Yeterli stok yok: ${item.name}` });
      }
      product.stock -= item.qty;
      await product.save();
    }
    io.emit('productsUpdated');

    const total = cart.reduce((sum, item) => sum + item.price * item.qty, 0);
    
    // Sepetteki ürünlerin detaylı bilgilerini al
    const detailedProducts = await Promise.all(cart.map(async (item) => {
      const product = await Product.findById(item._id);
      return {
        _id: item._id,
        name: item.name,
        price: item.price,
        qty: item.qty,
        image: product?.images && product.images.length > 0 ? product.images[0] : item.image, // Ürün resmini veritabanından al
        selectedSize: item.selectedSize || null, // Sepetten gelen seçilen beden
        cutType: product?.cutType || null,
        productionPlace: product?.productionPlace || null,
        material: product?.material || null,
        modelHeight: product?.modelHeight || null,
        modelSize: product?.modelSize || null,
        pattern: product?.pattern || null,
        sustainability: product?.sustainability || null,
        sleeveType: product?.sleeveType || null,
        collarType: product?.collarType || null,
        legLength: product?.legLength || null,
        color: product?.color || null,
        productType: product?.productType || null,
        sizes: product?.sizes || [],
        stock: product?.stock || 0,
        description: product?.description || null
      };
    }));
    
    const order = await Order.create({
      products: detailedProducts,
      userEmail: email,
      address,
      total,
      status: 'Satın Alındı'
    });

    // Email gönder
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER || 'your-email@gmail.com',
        to: email,
        subject: 'Siparişiniz Alındı!',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Siparişiniz Başarıyla Alındı!</h2>
            <p>Merhaba ${address.name} ${address.surname},</p>
            <p>Siparişiniz başarıyla alındı ve işleme alındı.</p>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <h3>Sipariş Detayları:</h3>
              <p><strong>Sipariş No:</strong> ${order._id}</p>
              <p><strong>Tarih:</strong> ${new Date().toLocaleString('tr-TR')}</p>
              <p><strong>Toplam Tutar:</strong> ${total.toFixed(2)}₺</p>
              
              <h4>Ürünler:</h4>
              <ul>
                ${cart.map(item => `<li>${item.name} x ${item.qty} - ${item.price}₺</li>`).join('')}
              </ul>
            </div>
            
            <div style="background: #e9ecef; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <h3>Teslimat Adresi:</h3>
              <p>${address.name} ${address.surname}</p>
              <p>${address.phone}</p>
              <p>${address.address}</p>
              <p>${address.district}, ${address.city} ${address.zip}</p>
            </div>
            
            <p>Siparişinizin durumunu takip etmek için web sitemizi ziyaret edebilirsiniz.</p>
            <p>Teşekkürler!</p>
          </div>
        `
      };
      
      await transporter.sendMail(mailOptions);
              // Sipariş onay emaili gönderildi
    } catch (emailErr) {
      console.error('Email gönderilemedi:', emailErr);
    }

    res.status(201).json(order);
  } catch (err) {
    res.status(500).json({ error: 'Sipariş kaydedilemedi' });
  }
});

// Admin için siparişleri listeleme endpoint'i
app.get('/api/orders', async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Siparişler alınamadı' });
  }
});

// Kullanıcıya özel sipariş geçmişi endpointi
app.get('/api/my-orders', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email gerekli' });
  try {
    const orders = await Order.find({ userEmail: email }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Siparişler alınamadı' });
  }
});

// Şifre değiştirme endpointi
app.post('/api/change-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;
  if (!email || !oldPassword || !newPassword) return res.status(400).json({ error: 'Tüm alanlar zorunlu' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Kullanıcı bulunamadı' });
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) return res.status(400).json({ error: 'Mevcut şifre yanlış' });
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    await user.save();
    res.json({ message: 'Şifre başarıyla değiştirildi' });
  } catch (err) {
    res.status(500).json({ error: 'Şifre değiştirilemedi' });
  }
});

// Sipariş durumu güncelleme endpointi (admin)
app.put('/api/orders/:id/status', async (req, res) => {
  const { status } = req.body;
  const orderId = req.params.id;
  
  console.log('Sipariş durumu güncelleme isteği:', orderId, status);
  
  try {
    const order = await Order.findByIdAndUpdate(orderId, { status }, { new: true });
    if (!order) {
      console.log('Sipariş bulunamadı:', orderId);
      return res.status(404).json({ error: 'Sipariş bulunamadı' });
    }
    
    console.log('Sipariş güncellendi:', order._id, order.status);
    
    // Socket.IO ile gerçek zamanlı güncelleme
    io.emit('orderStatusUpdated', order);
    
    res.json(order);
  } catch (err) {
    console.error('Sipariş durumu güncelleme hatası:', err);
    res.status(500).json({ error: 'Sipariş durumu güncellenemedi' });
  }
});

// Destek talebi oluştur (kullanıcı)
app.post('/api/support', async (req, res) => {
  const { orderId, userEmail, message } = req.body;
  if (!orderId || !userEmail || !message) return res.status(400).json({ error: 'Tüm alanlar zorunlu' });
  try {
    // Aynı sipariş için mevcut destek talebi var mı kontrol et
    const existingTicket = await SupportTicket.findOne({ orderId, userEmail });
    if (existingTicket) {
      return res.status(400).json({ error: 'Bu sipariş için zaten bir destek talebiniz var' });
    }
    const ticket = await SupportTicket.create({
      orderId,
      userEmail,
      message,
      messages: [{ sender: 'user', message, date: new Date() }],
      chatOpen: true
    });
    
    // Socket.IO ile gerçek zamanlı güncelleme
    io.emit('supportMessageUpdated', ticket);
    
    res.status(201).json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Destek talebi oluşturulamadı' });
  }
});

// Destek taleplerini listele (admin ve kullanıcı)
app.get('/api/support', async (req, res) => {
  const { userEmail } = req.query;
  try {
    const filter = userEmail ? { userEmail } : {};
    const tickets = await SupportTicket.find(filter).sort({ createdAt: -1 });
    
    // Her destek talebi için sipariş bilgilerini getir
    for (let ticket of tickets) {
      try {
        const order = await Order.findById(ticket.orderId);
        if (order) {
          ticket.orderInfo = {
            products: order.products,
            total: order.total,
            address: order.address
          };
        }
      } catch (err) {
        // Sipariş bulunamadı
      }
    }
    
    // Her destek talebinde kullanıcı cevaplarını tarihe göre sırala
    tickets.forEach(ticket => {
      if (ticket.userReplies && ticket.userReplies.length > 0) {
        ticket.userReplies.sort((a, b) => new Date(a.date) - new Date(b.date));
      }
    });
    
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ error: 'Destek talepleri alınamadı' });
  }
});

// Kullanıcı destek talebine mesaj yazar (chat)
app.put('/api/support/:id/user-reply', async (req, res) => {
  const { userReply } = req.body;
  try {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ error: 'Destek talebi bulunamadı' });
    if (!ticket.chatOpen) return res.status(400).json({ error: 'Sohbet kapalı' });
    ticket.messages = ticket.messages || [];
    ticket.messages.push({ sender: 'user', message: userReply, date: new Date() });
    ticket.status = 'Açık';
    await ticket.save();
    
    // Socket.IO ile gerçek zamanlı güncelleme - tüm bağlı kullanıcılara gönder
    // Emitting supportMessageUpdated for user message
    io.emit('supportMessageUpdated', ticket);
    
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Cevap kaydedilemedi' });
  }
});

// Admin destek talebine mesaj yazar (chat)
app.put('/api/support/:id/reply', async (req, res) => {
  const { adminReply } = req.body;
  if (!adminReply || !adminReply.trim()) {
    return res.status(400).json({ error: 'Cevap metni gerekli' });
  }
  try {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ error: 'Destek talebi bulunamadı' });
    if (!ticket.chatOpen) return res.status(400).json({ error: 'Sohbet kapalı' });
    ticket.messages = ticket.messages || [];
    ticket.messages.push({ sender: 'admin', message: adminReply, date: new Date() });
    ticket.status = 'Yanıtlandı';
    await ticket.save();
    
    // Socket.IO ile gerçek zamanlı güncelleme - tüm bağlı kullanıcılara gönder
    // Emitting supportMessageUpdated for admin message
    io.emit('supportMessageUpdated', ticket);
    
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Cevap kaydedilemedi' });
  }
});

// Sohbeti aç/kapa endpointi
app.put('/api/support/:id/chat-toggle', async (req, res) => {
  const { chatOpen } = req.body;
  try {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ error: 'Destek talebi bulunamadı' });
    ticket.chatOpen = chatOpen;
    await ticket.save();
    
    // Socket.IO ile gerçek zamanlı güncelleme
    io.emit('supportMessageUpdated', ticket);
    
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Chat durumu güncellenemedi' });
  }
});

// Destek talebini çözüldü olarak işaretle
app.put('/api/support/:id/resolve', async (req, res) => {
  try {
    const ticket = await SupportTicket.findByIdAndUpdate(req.params.id, { status: 'Çözüldü' }, { new: true });
    if (!ticket) return res.status(404).json({ error: 'Destek talebi bulunamadı' });
    
    // Socket.IO ile gerçek zamanlı güncelleme
    io.emit('supportMessageUpdated', ticket);
    
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Durum güncellenemedi' });
  }
});

// Sipariş iptal endpointi (admin)
app.put('/api/orders/:id/cancel', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Sipariş bulunamadı' });
    if (order.status === 'İptal Edildi') {
      return res.status(400).json({ error: 'Sipariş zaten iptal edilmiş' });
    }
    order.status = 'İptal Edildi';
    // Demo para iadesi işlemi
    order.refundStatus = 'Demo İade Edildi';
    await order.save();
    // Stokları geri ekle
    for (const item of order.products) {
      const product = await Product.findById(item._id);
      if (product) {
        product.stock += item.qty;
        await product.save();
      }
    }
    // Demo para iadesi yapıldı
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Sipariş iptal edilemedi' });
  }
});

// Resim yükleme endpoint'i - Frontend'den gelen URL'leri doğrudan kabul et
app.post('/api/upload-images', (req, res) => {
  try {
    const { imageUrls } = req.body;
    
    if (!imageUrls || !Array.isArray(imageUrls) || imageUrls.length === 0) {
      return res.status(400).json({ error: 'Resim URL\'leri gerekli' });
    }

    res.json({ urls: imageUrls });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Resim yükleme hatası' });
  }
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'Backend is working!' });
});

// 48 saatten eski kapalı destek taleplerini silen arka plan görevini başlat
setInterval(async () => {
  const now = new Date();
  const cutoff = new Date(now.getTime() - 48 * 60 * 60 * 1000); // 48 saat önce
  try {
    const result = await SupportTicket.deleteMany({
      closedAt: { $lte: cutoff },
      status: { $in: ['Çözüldü', 'İptal Edildi'] }
    });
    if (result.deletedCount > 0) {
      // SupportTicket Cleanup completed
    }
  } catch (err) {
    console.error('[SupportTicket Cleanup] Silme hatası:', err);
  }
}, 60 * 60 * 1000); // Her saat çalışır

// Socket bağlantısı
io.on('connection', (socket) => {
  // Kullanıcı bağlandı
  
  socket.on('disconnect', () => {
    // Kullanıcı ayrıldı
  });
  
  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

// Destek talepleri endpoint'leri
app.get('/api/support-tickets', async (req, res) => {
  // ... existing code ...
});

// Kategori endpoint'leri
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find().sort({ createdAt: -1 });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: 'Kategoriler yüklenirken hata oluştu' });
  }
});

app.post('/api/categories', async (req, res) => {
  try {
    const { name, description } = req.body;
    
    if (!name || !name.trim()) {
      return res.status(400).json({ message: 'Kategori adı gereklidir' });
    }
    
    // Aynı isimde kategori var mı kontrol et
    const existingCategory = await Category.findOne({ name: name.trim() });
    if (existingCategory) {
      return res.status(400).json({ message: 'Bu isimde bir kategori zaten mevcut' });
    }
    
    const category = new Category({
      name: name.trim(),
      description: description ? description.trim() : ''
    });
    
    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ message: 'Kategori eklenirken hata oluştu' });
  }
});

app.put('/api/categories/:id', async (req, res) => {
  try {
    const { name, description } = req.body;
    const { id } = req.params;
    
    if (!name || !name.trim()) {
      return res.status(400).json({ message: 'Kategori adı gereklidir' });
    }
    
    // Aynı isimde başka kategori var mı kontrol et
    const existingCategory = await Category.findOne({ 
      name: name.trim(), 
      _id: { $ne: id } 
    });
    if (existingCategory) {
      return res.status(400).json({ message: 'Bu isimde bir kategori zaten mevcut' });
    }
    
    const category = await Category.findByIdAndUpdate(
      id,
      {
        name: name.trim(),
        description: description ? description.trim() : ''
      },
      { new: true }
    );
    
    if (!category) {
      return res.status(404).json({ message: 'Kategori bulunamadı' });
    }
    
    res.json(category);
  } catch (error) {
    res.status(500).json({ message: 'Kategori güncellenirken hata oluştu' });
  }
});

app.delete('/api/categories/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Bu kategoriye ait ürün var mı kontrol et
    const productsWithCategory = await Product.find({ category: id });
    if (productsWithCategory.length > 0) {
      return res.status(400).json({ 
        message: `Bu kategoriye ait ${productsWithCategory.length} ürün bulunmaktadır. Önce ürünleri başka kategoriye taşıyın veya kategorisini kaldırın.` 
      });
    }
    
    const category = await Category.findByIdAndDelete(id);
    if (!category) {
      return res.status(404).json({ message: 'Kategori bulunamadı' });
    }
    
    res.json({ message: 'Kategori başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Kategori silinirken hata oluştu' });
  }
});

server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
}); 