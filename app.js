const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'));

// User Model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model('User', userSchema);

// JWT Middleware
function isAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.redirect('/login');
  }
}

// Routes
app.get('/', (req, res) => {
  res.render('home');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // ✅ CORRECT regex (no double backslashes)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const passwordRegex = /^.{6,}$/; // Only check length (6+ characters)

  if (!emailRegex.test(email)) {
    return res.send('❌ Invalid email format');
  }

  if (!passwordRegex.test(password)) {
    return res.send('❌ Password must be at least 6 characters');
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  try {
    await User.create({ name, email, password: hashedPassword });
    res.redirect('/login');
  } catch (err) {
    res.send('❌ Email already exists or error occurred.');
  }
});


app.get('/login', (req, res) => {
  res.render('login');
});
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.send('Invalid email or password');
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.send('Invalid email or password');
  const token = jwt.sign({ id: user._id, name: user.name }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.cookie('token', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict'
  });
  res.redirect('/dashboard');
});

app.get('/dashboard', isAuthenticated, (req, res) => {
  res.render('dashboard', { name: req.user.name });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
