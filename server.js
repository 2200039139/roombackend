const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based version
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = process.env.PORT || 5000;

// JWT Secret (use environment variable in production)
const JWT_SECRET =
  process.env.JWT_SECRET ||
  'a4bf7c0d30d87039b415c39eb5afbf3dce4933e2d12382bc04eed9557420b1b9c98c27762fff2653d0cc260dec481f698d94957dc2f3ccac856b9e6385637a5b';

// Google OAuth Client
const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID ||
    '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com'
);

// CORS Configuration
const corsOptions = {
  origin: [
    'https://splitta1.vercel.app',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};

// Middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.options('*', cors(corsOptions)); // Handle preflight requests

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'crossover.proxy.rlwy.net',
  port: process.env.DB_PORT || 45503,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'pETMRzPHrccamZuZqumFloDKdPtekNXv',
  database: process.env.DB_NAME || 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Initialize database tables
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fullName VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255),
        googleId VARCHAR(255),
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS roommates (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        userId INT NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS expenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        description VARCHAR(255) NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        paidBy INT NOT NULL,
        date DATE NOT NULL,
        splitAmong JSON DEFAULT NULL,
        userId INT NOT NULL,
        FOREIGN KEY (paidBy) REFERENCES roommates(id) ON DELETE CASCADE,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS settlements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fromId INT NOT NULL,
        toId INT NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        date DATE NOT NULL,
        userId INT NOT NULL,
        FOREIGN KEY (fromId) REFERENCES roommates(id) ON DELETE CASCADE,
        FOREIGN KEY (toId) REFERENCES roommates(id) ON DELETE CASCADE,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    connection.release();
    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    process.exit(1);
  }
}

initializeDatabase();

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res
      .status(401)
      .json({ error: 'Access denied. No token provided.' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// ====================== USER AUTH ======================

// Register
app.post('/api/users/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res
        .status(400)
        .json({ error: 'Please provide all required fields' });
    }

    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    if (existingUsers.length > 0) {
      return res
        .status(400)
        .json({ error: 'User with this email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const [result] = await pool.query(
      'INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)',
      [fullName, email, hashedPassword]
    );

    const userId = result.insertId;
    const token = jwt.sign({ id: userId, email, fullName }, JWT_SECRET, {
      expiresIn: '24h',
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: userId, fullName, email },
      token,
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [
      email,
    ]);

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, fullName: user.fullName },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      user: { id: user.id, fullName: user.fullName, email: user.email },
      token,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Google OAuth
app.post('/api/users/google-auth', async (req, res) => {
  try {
    const { token } = req.body;

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience:
        process.env.GOOGLE_CLIENT_ID ||
        '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com',
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE googleId = ? OR email = ?',
      [googleId, email]
    );

    let userId;
    if (existingUsers.length > 0) {
      const user = existingUsers[0];
      userId = user.id;

      if (!user.googleId) {
        await pool.query('UPDATE users SET googleId = ? WHERE id = ?', [
          googleId,
          userId,
        ]);
      }
    } else {
      const [result] = await pool.query(
        'INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
        [name, email, googleId]
      );
      userId = result.insertId;
    }

    const authToken = jwt.sign(
      { id: userId, email, fullName: name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      user: { id: userId, fullName: name, email },
      token: authToken,
    });
  } catch (error) {
    console.error('Google authentication error:', error);
    res.status(500).json({ error: 'Failed to authenticate with Google' });
  }
});

// ====================== ROOMMATES ======================
app.get('/api/roommates', authenticateToken, async (req, res) => {
  const [roommates] = await pool.query(
    'SELECT * FROM roommates WHERE userId = ?',
    [req.user.id]
  );
  res.json(roommates);
});

app.post('/api/roommates', authenticateToken, async (req, res) => {
  const { name } = req.body;
  const [result] = await pool.query(
    'INSERT INTO roommates (name, userId) VALUES (?, ?)',
    [name, req.user.id]
  );
  res.status(201).json({ id: result.insertId, name, userId: req.user.id });
});

app.delete('/api/roommates/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM roommates WHERE id = ? AND userId = ?', [
    req.params.id,
    req.user.id,
  ]);
  res.json({ message: 'Roommate deleted successfully' });
});

// ====================== EXPENSES ======================
app.get('/api/expenses', authenticateToken, async (req, res) => {
  const [expenses] = await pool.query(
    'SELECT * FROM expenses WHERE userId = ?',
    [req.user.id]
  );
  res.json(
    expenses.map((exp) => ({
      ...exp,
      splitAmong: exp.splitAmong ? JSON.parse(exp.splitAmong) : [],
    }))
  );
});

app.post('/api/expenses', authenticateToken, async (req, res) => {
  const { description, amount, paidBy, date, splitAmong } = req.body;
  const [result] = await pool.query(
    'INSERT INTO expenses (description, amount, paidBy, date, splitAmong, userId) VALUES (?, ?, ?, ?, ?, ?)',
    [description, amount, paidBy, date, JSON.stringify(splitAmong), req.user.id]
  );
  res.status(201).json({
    id: result.insertId,
    description,
    amount,
    paidBy,
    date,
    splitAmong,
    userId: req.user.id,
  });
});

app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM expenses WHERE id = ? AND userId = ?', [
    req.params.id,
    req.user.id,
  ]);
  res.json({ message: 'Expense deleted successfully' });
});

// ====================== SETTLEMENTS ======================
app.get('/api/settlements', authenticateToken, async (req, res) => {
  const [settlements] = await pool.query(
    'SELECT * FROM settlements WHERE userId = ?',
    [req.user.id]
  );
  res.json(settlements);
});

app.post('/api/settlements', authenticateToken, async (req, res) => {
  const { fromId, toId, amount, date } = req.body;
  const [result] = await pool.query(
    'INSERT INTO settlements (fromId, toId, amount, date, userId) VALUES (?, ?, ?, ?, ?)',
    [fromId, toId, amount, date, req.user.id]
  );
  res.status(201).json({ id: result.insertId, fromId, toId, amount, date });
});

app.delete('/api/settlements/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM settlements WHERE id = ? AND userId = ?', [
    req.params.id,
    req.user.id,
  ]);
  res.json({ message: 'Settlement deleted successfully' });
});

// ====================== ERROR HANDLER ======================
app.use((err, req, res, next) => {
  console.error('🔥 Server error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
