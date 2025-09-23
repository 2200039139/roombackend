const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = process.env.PORT || 5000;

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'a4bf7c0d30d87039b415c39eb5afbf3dce4933e2d12382bc04eed9557420b1b9c98c27762fff2653d0cc260dec481f698d94957dc2f3ccac856b9e6385637a5b';

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID || '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com');

// Enhanced CORS Configuration
const allowedOrigins = [
  'https://splitta1.vercel.app',
  'http://localhost:3000',
  'https://splitta1.vercel.app/',
  'http://localhost:3000/'
];

// CORS middleware with proper configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      // Check if origin matches without protocol
      const originWithoutProtocol = origin.replace(/^https?:\/\//, '');
      const isAllowed = allowedOrigins.some(allowed => {
        const allowedWithoutProtocol = allowed.replace(/^https?:\/\//, '').replace(/\/$/, '');
        return allowedWithoutProtocol === originWithoutProtocol.replace(/\/$/, '');
      });
      
      if (isAllowed) {
        callback(null, true);
      } else {
        console.log('CORS blocked for origin:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

// Additional headers middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.some(allowed => origin === allowed || origin === allowed.replace(/\/$/, ''))) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

app.use(bodyParser.json());

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'gondola.proxy.rlwy.net',
  port: process.env.DB_PORT || 54475,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'ryRFAgfgQJWwwDHJaqSReWJxShpiaNMj',
  database: process.env.DB_NAME || 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Initialize Database Tables
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
    console.log('Database tables initialized');
  } catch (error) {
    console.error('Error initializing database:', error);
    process.exit(1);
  }
}

initializeDatabase();

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Health Check Route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// USER AUTHENTICATION ROUTES

// User Registration
app.post('/api/users/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'Please provide all required fields' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const [result] = await pool.query(
      'INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)',
      [fullName, email, hashedPassword]
    );

    const userId = result.insertId;
    const token = jwt.sign({ id: userId, email, fullName }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: userId, fullName, email },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Google Authentication
app.post('/api/users/google-auth', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE googleId = ? OR email = ?',
      [googleId, email]
    );

    if (existingUsers.length > 0) {
      const user = existingUsers[0];
      if (!user.googleId) {
        await pool.query('UPDATE users SET googleId = ? WHERE id = ?', [googleId, user.id]);
      }

      const jwtToken = jwt.sign(
        { id: user.id, email: user.email, fullName: user.fullName },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      return res.json({
        message: 'Login successful',
        user: { id: user.id, fullName: user.fullName, email: user.email },
        token: jwtToken
      });
    } else {
      const [result] = await pool.query(
        'INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
        [name, email, googleId]
      );

      const userId = result.insertId;
      const jwtToken = jwt.sign({ id: userId, email, fullName: name }, JWT_SECRET, { expiresIn: '24h' });

      res.status(201).json({
        message: 'User registered successfully with Google',
        user: { id: userId, fullName: name, email },
        token: jwtToken
      });
    }
  } catch (error) {
    console.error('Google authentication error:', error);
    res.status(500).json({ error: 'Failed to authenticate with Google' });
  }
});

// User Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = users[0];
    
    // Check if user has a password (might be Google user)
    if (!user.password) {
      return res.status(401).json({ error: 'Please use Google login for this account' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, fullName: user.fullName }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      user: { id: user.id, fullName: user.fullName, email: user.email },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get user profile
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, fullName, email, createdAt FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(users[0]);
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ROOMMATE ROUTES

// Get all roommates for a user
app.get('/api/roommates', authenticateToken, async (req, res) => {
  try {
    const [roommates] = await pool.query('SELECT * FROM roommates WHERE userId = ?', [req.user.id]);
    res.json(roommates);
  } catch (error) {
    console.error('Get roommates error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new roommate
app.post('/api/roommates', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Roommate name is required' });

    const [result] = await pool.query(
      'INSERT INTO roommates (name, userId) VALUES (?, ?)',
      [name, req.user.id]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      userId: req.user.id
    });
  } catch (error) {
    console.error('Add roommate error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// EXPENSE ROUTES

// Get all expenses for a user
app.get('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const [expenses] = await pool.query(
      `SELECT e.*, r.name as paidByName 
       FROM expenses e 
       JOIN roommates r ON e.paidBy = r.id 
       WHERE e.userId = ? 
       ORDER BY e.date DESC`,
      [req.user.id]
    );
    res.json(expenses);
  } catch (error) {
    console.error('Get expenses error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new expense
app.post('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const { description, amount, paidBy, date, splitAmong } = req.body;
    
    if (!description || !amount || !paidBy || !date) {
      return res.status(400).json({ error: 'Please provide all required fields' });
    }

    const [result] = await pool.query(
      'INSERT INTO expenses (description, amount, paidBy, date, splitAmong, userId) VALUES (?, ?, ?, ?, ?, ?)',
      [description, parseFloat(amount), paidBy, date, JSON.stringify(splitAmong), req.user.id]
    );

    res.status(201).json({
      id: result.insertId,
      description,
      amount: parseFloat(amount),
      paidBy,
      date,
      splitAmong,
      userId: req.user.id
    });
  } catch (error) {
    console.error('Add expense error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// SETTLEMENT ROUTES

// Get all settlements for a user
app.get('/api/settlements', authenticateToken, async (req, res) => {
  try {
    const [settlements] = await pool.query(
      `SELECT s.*, r1.name as fromName, r2.name as toName 
       FROM settlements s 
       JOIN roommates r1 ON s.fromId = r1.id 
       JOIN roommates r2 ON s.toId = r2.id 
       WHERE s.userId = ? 
       ORDER BY s.date DESC`,
      [req.user.id]
    );
    res.json(settlements);
  } catch (error) {
    console.error('Get settlements error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new settlement
app.post('/api/settlements', authenticateToken, async (req, res) => {
  try {
    const { fromId, toId, amount, date } = req.body;
    
    if (!fromId || !toId || !amount || !date) {
      return res.status(400).json({ error: 'Please provide all required fields' });
    }

    const [result] = await pool.query(
      'INSERT INTO settlements (fromId, toId, amount, date, userId) VALUES (?, ?, ?, ?, ?)',
      [fromId, toId, parseFloat(amount), date, req.user.id]
    );

    res.status(201).json({
      id: result.insertId,
      fromId,
      toId,
      amount: parseFloat(amount),
      date,
      userId: req.user.id
    });
  } catch (error) {
    console.error('Add settlement error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Calculate balances
app.get('/api/balances', authenticateToken, async (req, res) => {
  try {
    const [roommates] = await pool.query('SELECT * FROM roommates WHERE userId = ?', [req.user.id]);
    const [expenses] = await pool.query('SELECT * FROM expenses WHERE userId = ?', [req.user.id]);
    const [settlements] = await pool.query('SELECT * FROM settlements WHERE userId = ?', [req.user.id]);

    const balances = {};
    roommates.forEach(roommate => {
      balances[roommate.id] = 0;
    });

    // Calculate from expenses
    expenses.forEach(expense => {
      const splitAmong = JSON.parse(expense.splitAmong || '{}');
      const totalShares = Object.values(splitAmong).reduce((sum, share) => sum + share, 0);
      
      if (totalShares > 0) {
        const shareValue = expense.amount / totalShares;
        
        Object.keys(splitAmong).forEach(roommateId => {
          const share = splitAmong[roommateId];
          if (parseInt(roommateId) === expense.paidBy) {
            balances[roommateId] += expense.amount - (share * shareValue);
          } else {
            balances[roommateId] -= share * shareValue;
          }
        });
      }
    });

    // Adjust from settlements
    settlements.forEach(settlement => {
      balances[settlement.fromId] -= settlement.amount;
      balances[settlement.toId] += settlement.amount;
    });

    const result = roommates.map(roommate => ({
      id: roommate.id,
      name: roommate.name,
      balance: parseFloat(balances[roommate.id].toFixed(2))
    }));

    res.json(result);
  } catch (error) {
    console.error('Calculate balances error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
  console.log(`Allowed origins: ${allowedOrigins.join(', ')}`);
});
