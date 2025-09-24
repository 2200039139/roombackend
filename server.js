const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');

const app = express();
const port = process.env.PORT || 5000;

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Environment variable validation
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    logger.error(`Missing required environment variable: ${envVar}`);
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  }
});

// JWT Secret with fallback for development
const JWT_SECRET = process.env.JWT_SECRET || 'a4bf7c0d30d87039b415c39eb5afbf3dce4933e2d12382bc04eed9557420b1b9c98c27762fff2653d0cc260dec481f698d94957dc2f3ccac856b9e6385637a5b';

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID || '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com');

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: { error: 'Too many authentication attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

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
        logger.warn('CORS blocked for origin:', origin);
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

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
  next();
});

// MySQL Connection Pool with enhanced configuration
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'gondola.proxy.rlwy.net',
  port: process.env.DB_PORT || 54475,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'ryRFAgfgQJWwwDHJaqSReWJxShpiaNMj',
  database: process.env.DB_NAME || 'railway',
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
});

// Database connection event handlers
pool.on('connection', (connection) => {
  logger.info('MySQL connection established');
});

pool.on('error', (err) => {
  logger.error('MySQL pool error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    logger.info('Attempting to reconnect to database...');
  }
});

// Transaction helper function
const withTransaction = async (callback) => {
  const connection = await pool.getConnection();
  await connection.beginTransaction();
  
  try {
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
};

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
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_googleId (googleId)
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS roommates (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        userId INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_userId (userId)
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
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (paidBy) REFERENCES roommates(id) ON DELETE CASCADE,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_userId (userId),
        INDEX idx_date (date),
        INDEX idx_paidBy (paidBy)
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
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (fromId) REFERENCES roommates(id) ON DELETE CASCADE,
        FOREIGN KEY (toId) REFERENCES roommates(id) ON DELETE CASCADE,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_userId (userId),
        INDEX idx_fromId (fromId),
        INDEX idx_toId (toId)
      )
    `);

    connection.release();
    logger.info('Database tables initialized successfully');
  } catch (error) {
    logger.error('Error initializing database:', error);
    process.exit(1);
  }
}

initializeDatabase();

// Input sanitization function
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input.trim().replace(/[<>&"']/g, '');
  }
  return input;
};

// Response standardization middleware
app.use((req, res, next) => {
  res.success = (data, message = 'Success', statusCode = 200) => {
    res.status(statusCode).json({
      success: true,
      message,
      data,
      timestamp: new Date().toISOString()
    });
  };

  res.error = (message, statusCode = 400, details = null) => {
    res.status(statusCode).json({
      success: false,
      message,
      details,
      timestamp: new Date().toISOString()
    });
  };
  
  next();
});

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.error('Access denied. No token provided.', 401);
    }

    const verified = jwt.verify(token, JWT_SECRET);
    
    // Verify user still exists in database
    const [users] = await pool.query('SELECT id, email, fullName FROM users WHERE id = ?', [verified.id]);
    if (users.length === 0) {
      return res.error('User not found.', 401);
    }

    req.user = users[0];
    next();
  } catch (error) {
    logger.warn('JWT verification failed:', error.message);
    return res.error('Invalid or expired token.', 403);
  }
};

// Validation middleware
const validateRegistration = [
  body('fullName')
    .isLength({ min: 2, max: 255 })
    .withMessage('Full name must be between 2 and 255 characters')
    .trim()
    .escape(),
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
];

const validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

const validateExpense = [
  body('description')
    .isLength({ min: 1, max: 255 })
    .withMessage('Description must be between 1 and 255 characters')
    .trim()
    .escape(),
  body('amount')
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be a positive number'),
  body('paidBy')
    .isInt({ min: 1 })
    .withMessage('Invalid payer selected'),
  body('date')
    .isISO8601()
    .withMessage('Invalid date format'),
  body('splitAmong')
    .isObject()
    .withMessage('Split configuration is required')
];

// Health Check Route
app.get('/api/health', (req, res) => {
  res.success({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development'
  }, 'Server is running healthy');
});

// USER AUTHENTICATION ROUTES

// User Registration
app.post('/api/users/register', authLimiter, validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { fullName, email, password } = req.body;

    const [existingUsers] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.error('User with this email already exists', 400);
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    const result = await withTransaction(async (connection) => {
      const [insertResult] = await connection.query(
        'INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)',
        [sanitizeInput(fullName), email, hashedPassword]
      );
      return insertResult;
    });

    const userId = result.insertId;
    const token = jwt.sign({ id: userId, email, fullName }, JWT_SECRET, { expiresIn: '24h' });

    logger.info('User registered successfully', { userId, email });

    res.success(
      { 
        user: { id: userId, fullName, email },
        token 
      },
      'User registered successfully',
      201
    );
  } catch (error) {
    logger.error('Registration error:', error);
    res.error('Server error during registration', 500);
  }
});

// Google Authentication
app.post('/api/users/google-auth', authLimiter, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.error('Google token is required', 400);
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    if (!email) {
      return res.error('Invalid Google token: email not found', 400);
    }

    const result = await withTransaction(async (connection) => {
      const [existingUsers] = await connection.query(
        'SELECT * FROM users WHERE googleId = ? OR email = ?',
        [googleId, email]
      );

      if (existingUsers.length > 0) {
        const user = existingUsers[0];
        if (!user.googleId) {
          await connection.query('UPDATE users SET googleId = ? WHERE id = ?', [googleId, user.id]);
        }

        return { user, isNew: false };
      } else {
        const [insertResult] = await connection.query(
          'INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
          [sanitizeInput(name), email, googleId]
        );

        const newUser = { id: insertResult.insertId, fullName: name, email, googleId };
        return { user: newUser, isNew: true };
      }
    });

    const jwtToken = jwt.sign(
      { id: result.user.id, email: result.user.email, fullName: result.user.fullName },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    logger.info('Google authentication successful', { userId: result.user.id, email, isNew: result.isNew });

    res.success({
      user: { id: result.user.id, fullName: result.user.fullName, email: result.user.email },
      token: jwtToken
    }, result.isNew ? 'User registered successfully with Google' : 'Login successful');

  } catch (error) {
    logger.error('Google authentication error:', error);
    res.error('Failed to authenticate with Google', 500);
  }
});

// User Login
app.post('/api/users/login', authLimiter, validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { email, password } = req.body;

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.error('Invalid email or password', 401);
    }

    const user = users[0];
    
    if (!user.password) {
      return res.error('Please use Google login for this account', 401);
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.error('Invalid email or password', 401);
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, fullName: user.fullName }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    logger.info('User login successful', { userId: user.id, email });

    res.success({
      user: { id: user.id, fullName: user.fullName, email: user.email },
      token
    }, 'Login successful');

  } catch (error) {
    logger.error('Login error:', error);
    res.error('Server error during login', 500);
  }
});

// Get user profile
app.get('/api/users/me', authenticateToken, apiLimiter, async (req, res) => {
  try {
    res.success(req.user, 'User profile retrieved successfully');
  } catch (error) {
    logger.error('Get user profile error:', error);
    res.error('Server error', 500);
  }
});

// Update user profile
app.put('/api/users/me', authenticateToken, apiLimiter, [
  body('fullName')
    .optional()
    .isLength({ min: 2, max: 255 })
    .withMessage('Full name must be between 2 and 255 characters')
    .trim()
    .escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { fullName } = req.body;
    
    if (fullName) {
      await pool.query(
        'UPDATE users SET fullName = ? WHERE id = ?',
        [sanitizeInput(fullName), req.user.id]
      );
    }

    const [updatedUser] = await pool.query(
      'SELECT id, fullName, email, createdAt FROM users WHERE id = ?',
      [req.user.id]
    );

    logger.info('User profile updated', { userId: req.user.id });

    res.success(updatedUser[0], 'Profile updated successfully');
  } catch (error) {
    logger.error('Update user profile error:', error);
    res.error('Server error', 500);
  }
});

// ROOMMATE ROUTES

// Get all roommates for a user
app.get('/api/roommates', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const [roommates] = await pool.query(
      'SELECT * FROM roommates WHERE userId = ? ORDER BY name ASC',
      [req.user.id]
    );
    res.success(roommates, 'Roommates retrieved successfully');
  } catch (error) {
    logger.error('Get roommates error:', error);
    res.error('Server error', 500);
  }
});

// Add new roommate
app.post('/api/roommates', authenticateToken, apiLimiter, [
  body('name')
    .isLength({ min: 1, max: 255 })
    .withMessage('Roommate name must be between 1 and 255 characters')
    .trim()
    .escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { name } = req.body;

    const [result] = await pool.query(
      'INSERT INTO roommates (name, userId) VALUES (?, ?)',
      [sanitizeInput(name), req.user.id]
    );

    logger.info('Roommate added', { roommateId: result.insertId, userId: req.user.id });

    res.success({
      id: result.insertId,
      name,
      userId: req.user.id
    }, 'Roommate added successfully', 201);
  } catch (error) {
    logger.error('Add roommate error:', error);
    res.error('Server error', 500);
  }
});

// Update roommate
app.put('/api/roommates/:id', authenticateToken, apiLimiter, [
  body('name')
    .isLength({ min: 1, max: 255 })
    .withMessage('Roommate name must be between 1 and 255 characters')
    .trim()
    .escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { id } = req.params;
    const { name } = req.body;

    const [result] = await pool.query(
      'UPDATE roommates SET name = ? WHERE id = ? AND userId = ?',
      [sanitizeInput(name), id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.error('Roommate not found', 404);
    }

    logger.info('Roommate updated', { roommateId: id, userId: req.user.id });

    res.success(null, 'Roommate updated successfully');
  } catch (error) {
    logger.error('Update roommate error:', error);
    res.error('Server error', 500);
  }
});

// Delete roommate
app.delete('/api/roommates/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await pool.query(
      'DELETE FROM roommates WHERE id = ? AND userId = ?',
      [id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.error('Roommate not found', 404);
    }

    logger.info('Roommate deleted', { roommateId: id, userId: req.user.id });

    res.success(null, 'Roommate deleted successfully');
  } catch (error) {
    logger.error('Delete roommate error:', error);
    res.error('Server error', 500);
  }
});

// EXPENSE ROUTES

// Get all expenses for a user
app.get('/api/expenses', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const [expenses] = await pool.query(
      `SELECT e.*, r.name as paidByName 
       FROM expenses e 
       JOIN roommates r ON e.paidBy = r.id 
       WHERE e.userId = ? 
       ORDER BY e.date DESC, e.createdAt DESC`,
      [req.user.id]
    );
    
    // Parse JSON fields
    const parsedExpenses = expenses.map(expense => ({
      ...expense,
      splitAmong: typeof expense.splitAmong === 'string' ? JSON.parse(expense.splitAmong) : expense.splitAmong
    }));

    res.success(parsedExpenses, 'Expenses retrieved successfully');
  } catch (error) {
    logger.error('Get expenses error:', error);
    res.error('Server error', 500);
  }
});

// Add new expense
app.post('/api/expenses', authenticateToken, apiLimiter, validateExpense, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { description, amount, paidBy, date, splitAmong } = req.body;

    // Verify that paidBy roommate belongs to user
    const [roommates] = await pool.query(
      'SELECT id FROM roommates WHERE id = ? AND userId = ?',
      [paidBy, req.user.id]
    );

    if (roommates.length === 0) {
      return res.error('Invalid payer selected', 400);
    }

    const result = await withTransaction(async (connection) => {
      const [insertResult] = await connection.query(
        'INSERT INTO expenses (description, amount, paidBy, date, splitAmong, userId) VALUES (?, ?, ?, ?, ?, ?)',
        [sanitizeInput(description), parseFloat(amount), paidBy, date, JSON.stringify(splitAmong), req.user.id]
      );
      return insertResult;
    });

    logger.info('Expense added', { expenseId: result.insertId, userId: req.user.id });

    res.success({
      id: result.insertId,
      description,
      amount: parseFloat(amount),
      paidBy,
      date,
      splitAmong,
      userId: req.user.id
    }, 'Expense added successfully', 201);
  } catch (error) {
    logger.error('Add expense error:', error);
    res.error('Server error', 500);
  }
});

// Update expense
app.put('/api/expenses/:id', authenticateToken, apiLimiter, validateExpense, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { id } = req.params;
    const { description, amount, paidBy, date, splitAmong } = req.body;

    const [result] = await pool.query(
      'UPDATE expenses SET description = ?, amount = ?, paidBy = ?, date = ?, splitAmong = ? WHERE id = ? AND userId = ?',
      [sanitizeInput(description), parseFloat(amount), paidBy, date, JSON.stringify(splitAmong), id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.error('Expense not found', 404);
    }

    logger.info('Expense updated', { expenseId: id, userId: req.user.id });

    res.success(null, 'Expense updated successfully');
  } catch (error) {
    logger.error('Update expense error:', error);
    res.error('Server error', 500);
  }
});

// Delete expense
app.delete('/api/expenses/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await pool.query(
      'DELETE FROM expenses WHERE id = ? AND userId = ?',
      [id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.error('Expense not found', 404);
    }

    logger.info('Expense deleted', { expenseId: id, userId: req.user.id });

    res.success(null, 'Expense deleted successfully');
  } catch (error) {
    logger.error('Delete expense error:', error);
    res.error('Server error', 500);
  }
});

// SETTLEMENT ROUTES

// Get all settlements for a user
app.get('/api/settlements', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const [settlements] = await pool.query(
      `SELECT s.*, r1.name as fromName, r2.name as toName 
       FROM settlements s 
       JOIN roommates r1 ON s.fromId = r1.id 
       JOIN roommates r2 ON s.toId = r2.id 
       WHERE s.userId = ? 
       ORDER BY s.date DESC, s.createdAt DESC`,
      [req.user.id]
    );
    res.success(settlements, 'Settlements retrieved successfully');
  } catch (error) {
    logger.error('Get settlements error:', error);
    res.error('Server error', 500);
  }
});

// Add new settlement
app.post('/api/settlements', authenticateToken, apiLimiter, [
  body('fromId').isInt({ min: 1 }).withMessage('Invalid sender'),
  body('toId').isInt({ min: 1 }).withMessage('Invalid receiver'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number'),
  body('date').isISO8601().withMessage('Invalid date format')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.error('Validation failed', 400, errors.array());
    }

    const { fromId, toId, amount, date } = req.body;

    if (fromId === toId) {
      return res.error('Sender and receiver cannot be the same', 400);
    }

    // Verify that roommates belong to user
    const [roommates] = await pool.query(
      'SELECT id FROM roommates WHERE id IN (?, ?) AND userId = ?',
      [fromId, toId, req.user.id]
    );

    if (roommates.length !== 2) {
      return res.error('Invalid roommates selected', 400);
    }

    const result = await withTransaction(async (connection) => {
      const [insertResult] = await connection.query(
        'INSERT INTO settlements (fromId, toId, amount, date, userId) VALUES (?, ?, ?, ?, ?)',
        [fromId, toId, parseFloat(amount), date, req.user.id]
      );
      return insertResult;
    });

    logger.info('Settlement added', { settlementId: result.insertId, userId: req.user.id });

    res.success({
      id: result.insertId,
      fromId,
      toId,
      amount: parseFloat(amount),
      date,
      userId: req.user.id
    }, 'Settlement added successfully', 201);
  } catch (error) {
    logger.error('Add settlement error:', error);
    res.error('Server error', 500);
  }
});

// Calculate balances
app.get('/api/balances', authenticateToken, apiLimiter, async (req, res) => {
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
      const splitAmong = typeof expense.splitAmong === 'string' ? JSON.parse(expense.splitAmong) : expense.splitAmong;
      const totalShares = Object.values(splitAmong).reduce((sum, share) => sum + share, 0);
      
      if (totalShares > 0) {
        const shareValue = expense.amount / totalShares;
        
        Object.keys(splitAmong).forEach(roommateId => {
          const share = splitAmong[roommateId];
          const numericRoommateId = parseInt(roommateId);
          
          if (numericRoommateId === expense.paidBy) {
            balances[numericRoommateId] += expense.amount - (share * shareValue);
          } else {
            balances[numericRoommateId] -= share * shareValue;
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

    res.success(result, 'Balances calculated successfully');
  } catch (error) {
    logger.error('Calculate balances error:', error);
    res.error('Server error', 500);
  }
});

// Get dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const [roommateCount] = await pool.query(
      'SELECT COUNT(*) as count FROM roommates WHERE userId = ?',
      [req.user.id]
    );

    const [expenseCount] = await pool.query(
      'SELECT COUNT(*) as count FROM expenses WHERE userId = ?',
      [req.user.id]
    );

    const [totalExpenses] = await pool.query(
      'SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE userId = ?',
      [req.user.id]
    );

    const [recentExpenses] = await pool.query(
      `SELECT e.*, r.name as paidByName 
       FROM expenses e 
       JOIN roommates r ON e.paidBy = r.id 
       WHERE e.userId = ? 
       ORDER BY e.date DESC 
       LIMIT 5`,
      [req.user.id]
    );

    res.success({
      roommateCount: roommateCount[0].count,
      expenseCount: expenseCount[0].count,
      totalExpenses: parseFloat(totalExpenses[0].total),
      recentExpenses: recentExpenses.map(expense => ({
        ...expense,
        splitAmong: typeof expense.splitAmong === 'string' ? JSON.parse(expense.splitAmong) : expense.splitAmong
      }))
    }, 'Dashboard statistics retrieved successfully');
  } catch (error) {
    logger.error('Get dashboard stats error:', error);
    res.error('Server error', 500);
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.error('Something went wrong!', 500);
});

// 404 handler
app.use('*', (req, res) => {
  res.error('Route not found', 404);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Received SIGINT. Starting graceful shutdown...');
  await pool.end();
  logger.info('Database connections closed.');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM. Starting graceful shutdown...');
  await pool.end();
  logger.info('Database connections closed.');
  process.exit(0);
});

// Start server
app.listen(port, '0.0.0.0', () => {
  logger.info(`Server running on port ${port}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Allowed origins: ${allowedOrigins.join(', ')}`);
});
