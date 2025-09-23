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
const JWT_SECRET = process.env.JWT_SECRET || 'a4bf7c0d30d87039b415c39eb5afbf3dce4933e2d12382bc04eed9557420b1b9c98c27762fff2653d0cc260dec481f698d94957dc2f3ccac856b9e6385637a5b';

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID || '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com');

// CORS Configuration
const corsOptions = {
  origin: [
    'https://splitta1.vercel.app',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

// Middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.options('*', cors(corsOptions)); // Handle preflight requests

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'gondola.proxy.rlwy.net',  // from Railway URL
  port: process.env.DB_PORT || 54475,                    // from Railway URL
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'ryRFAgfgQJWwwDHJaqSReWJxShpiaNMj',
  database: process.env.DB_NAME || 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
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
    console.log('Database tables initialized');
  } catch (error) {
    console.error('Error initializing database:', error);
    process.exit(1);
  }
}

initializeDatabase();

// Middleware to verify JWT token
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
    const token = jwt.sign(
      { id: userId, email, fullName },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    const user = {
      id: userId,
      fullName,
      email
    };
    
    res.status(201).json({
      message: 'User registered successfully',
      user,
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Google Authentication
app.post('/api/users/google-auth', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }
    
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID || '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com'
    });
    
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;
    
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE googleId = ? OR email = ?',
      [googleId, email]
    );
    
    if (existingUsers.length > 0) {
      const user = existingUsers[0];
      
      if (!user.googleId) {
        await pool.query(
          'UPDATE users SET googleId = ? WHERE id = ?',
          [googleId, user.id]
        );
      }
      
      const token = jwt.sign(
        { id: user.id, email: user.email, fullName: user.fullName },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      const userData = {
        id: user.id,
        fullName: user.fullName,
        email: user.email
      };
      
      return res.json({
        message: 'Login successful',
        user: userData,
        token
      });
    } else {
      const [result] = await pool.query(
        'INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
        [name, email, googleId]
      );
      
      const userId = result.insertId;
      const token = jwt.sign(
        { id: userId, email, fullName: name },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      const userData = {
        id: userId,
        fullName: name,
        email
      };
      
      res.status(201).json({
        message: 'User registered successfully with Google',
        user: userData,
        token
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
    
    const userData = {
      id: user.id,
      fullName: user.fullName,
      email: user.email
    };
    
    res.json({
      message: 'Login successful',
        user: userData,
        token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, fullName, email FROM users WHERE id = ?', [req.user.id]);
    
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(users[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ROOMMATE ROUTES

// Get all roommates
app.get('/api/roommates', authenticateToken, async (req, res) => {
  try {
    const [roommates] = await pool.query('SELECT * FROM roommates WHERE userId = ?', [req.user.id]);
    res.json(roommates);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a new roommate
app.post('/api/roommates', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    const userId = req.user.id;
    
    if (!name || name.trim() === '') {
      return res.status(400).json({ error: 'Roommate name is required' });
    }
    
    const [result] = await pool.query(
      'INSERT INTO roommates (name, userId) VALUES (?, ?)',
      [name, userId]
    );
    
    const id = result.insertId;
    res.status(201).json({ id, name, userId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Remove a roommate
app.delete('/api/roommates/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const userId = req.user.id;
    
    const [roommates] = await pool.query(
      'SELECT * FROM roommates WHERE id = ? AND userId = ?',
      [id, userId]
    );
    
    if (roommates.length === 0) {
      return res.status(404).json({ error: 'Roommate not found or not authorized' });
    }
    
    await pool.query('DELETE FROM roommates WHERE id = ?', [id]);
    res.json({ message: 'Roommate deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// EXPENSE ROUTES

// Get all expenses
app.get('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const [expenses] = await pool.query('SELECT * FROM expenses WHERE userId = ?', [req.user.id]);
    
    const expensesWithSplit = expenses.map(expense => ({
      ...expense,
      splitAmong: expense.splitAmong ? JSON.parse(expense.splitAmong) : []
    }));
    
    res.json(expensesWithSplit);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a new expense
app.post('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const { description, amount, paidBy, date, splitAmong } = req.body;
    const userId = req.user.id;
    
    if (!description || description.trim() === '') {
      return res.status(400).json({ error: 'Description is required' });
    }
    
    if (!amount || isNaN(parseFloat(amount))) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }
    
    if (!paidBy) {
      return res.status(400).json({ error: 'Paid by is required' });
    }
    
    if (!date) {
      return res.status(400).json({ error: 'Date is required' });
    }
    
    if (!splitAmong || !Array.isArray(splitAmong) || splitAmong.length === 0) {
      return res.status(400).json({ error: 'At least one participant is required' });
    }
    
    const [paidByRoommate] = await pool.query(
      'SELECT * FROM roommates WHERE id = ? AND userId = ?',
      [paidBy, userId]
    );
    
    if (paidByRoommate.length === 0) {
      return res.status(400).json({ error: 'Invalid roommate selected' });
    }
    
    const [participants] = await pool.query(
      'SELECT id FROM roommates WHERE id IN (?) AND userId = ?',
      [splitAmong, userId]
    );
    
    if (participants.length !== splitAmong.length) {
      return res.status(400).json({ error: 'Invalid participants selected' });
    }
    
    const splitAmongJson = JSON.stringify(splitAmong);
    
    const [result] = await pool.query(
      'INSERT INTO expenses (description, amount, paidBy, date, splitAmong, userId) VALUES (?, ?, ?, ?, ?, ?)',
      [description, amount, paidBy, date, splitAmongJson, userId]
    );
    
    const id = result.insertId;
    res.status(201).json({ 
      id, 
      description, 
      amount, 
      paidBy, 
      date, 
      splitAmong,
      userId 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete an expense
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const userId = req.user.id;
    
    const [expenses] = await pool.query(
      'SELECT * FROM expenses WHERE id = ? AND userId = ?',
      [id, userId]
    );
    
    if (expenses.length === 0) {
      return res.status(404).json({ error: 'Expense not found or not authorized' });
    }
    
    await pool.query('DELETE FROM expenses WHERE id = ?', [id]);
    res.json({ message: 'Expense deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SETTLEMENT ROUTES

// Get all settlements
app.get('/api/settlements', authenticateToken, async (req, res) => {
  try {
    const [settlements] = await pool.query('SELECT * FROM settlements WHERE userId = ?', [req.user.id]);
    res.json(settlements);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a new settlement
app.post('/api/settlements', authenticateToken, async (req, res) => {
  try {
    const { fromId, toId, amount, date } = req.body;
    const userId = req.user.id;
    
    if (!fromId || !toId) {
      return res.status(400).json({ error: 'Both from and to roommates are required' });
    }
    
    if (!amount || isNaN(parseFloat(amount))) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }
    
    if (!date) {
      return res.status(400).json({ error: 'Date is required' });
    }
    
    const [roommates] = await pool.query(
      'SELECT * FROM roommates WHERE id IN (?, ?) AND userId = ?',
      [fromId, toId, userId]
    );
    
    if (roommates.length !== 2) {
      return res.status(400).json({ error: 'Invalid roommates selected' });
    }
    
    const [result] = await pool.query(
      'INSERT INTO settlements (fromId, toId, amount, date, userId) VALUES (?, ?, ?, ?, ?)',
      [fromId, toId, amount, date, userId]
    );
    
    const id = result.insertId;
    res.status(201).json({ id, fromId, toId, amount, date, userId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a settlement
app.delete('/api/settlements/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const userId = req.user.id;
    
    const [settlements] = await pool.query(
      'SELECT * FROM settlements WHERE id = ? AND userId = ?',
      [id, userId]
    );
    
    if (settlements.length === 0) {
      return res.status(404).json({ error: 'Settlement not found or not authorized' });
    }
    
    await pool.query('DELETE FROM settlements WHERE id = ?', [id]);
    res.json({ message: 'Settlement deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
