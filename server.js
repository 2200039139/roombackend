const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = 5000;

// JWT Secret (use environment variable in production)
const JWT_SECRET = 'a4bf7c0d30d87039b415c39eb5afbf3dce4933e2d12382bc04eed9557420b1b9c98c27762fff2653d0cc260dec481f698d94957dc2f3ccac856b9e6385637a5b';

// Google OAuth Client
const googleClient = new OAuth2Client('37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com');

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
  host: 'crossover.proxy.rlwy.net',
  port: 45503,
  user: 'root',
  password: 'pETMRzPHrccamZuZqumFloDKdPtekNXv',
  database: 'railway'
});

// Connect to MySQL
db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL database:', err);
    return;
  }
  console.log('Connected to MySQL database');
  
  // Create tables if they don't exist
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      fullName VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255),
      googleId VARCHAR(255),
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  
  const createRoommatesTable = `
    CREATE TABLE IF NOT EXISTS roommates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      userId INT NOT NULL,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `;
  
  const createExpensesTable = `
    CREATE TABLE IF NOT EXISTS expenses (
      id INT AUTO_INCREMENT PRIMARY KEY,
      description VARCHAR(255) NOT NULL,
      amount DECIMAL(10, 2) NOT NULL,
      paidBy INT NOT NULL,
      date DATE NOT NULL,
      userId INT NOT NULL,
      splitAmong JSON DEFAULT NULL,
      FOREIGN KEY (paidBy) REFERENCES roommates(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `;
  
  const createSettlementsTable = `
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
  `;
  
  db.query(createUsersTable, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('Users table ready');
  });
  
  db.query(createRoommatesTable, (err) => {
    if (err) console.error('Error creating roommates table:', err);
    else console.log('Roommates table ready');
  });
  
  db.query(createExpensesTable, (err) => {
    if (err) console.error('Error creating expenses table:', err);
    else console.log('Expenses table ready');
  });
  
  db.query(createSettlementsTable, (err) => {
    if (err) console.error('Error creating settlements table:', err);
    else console.log('Settlements table ready');
  });
});

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
    
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      
      if (results.length > 0) {
        return res.status(400).json({ error: 'User with this email already exists' });
      }
      
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      
      db.query(
        'INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)',
        [fullName, email, hashedPassword],
        (err, result) => {
          if (err) {
            console.error('Error creating user:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
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
        }
      );
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add this after all your routes
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
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
      audience: '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com'
    });
    
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;
    
    db.query(
      'SELECT * FROM users WHERE googleId = ? OR email = ?',
      [googleId, email],
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        
        if (results.length > 0) {
          const user = results[0];
          
          if (!user.googleId) {
            db.query(
              'UPDATE users SET googleId = ? WHERE id = ?',
              [googleId, user.id],
              (err) => {
                if (err) {
                  console.error('Error updating user with Google ID:', err);
                }
              }
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
          db.query(
            'INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
            [name, email, googleId],
            (err, result) => {
              if (err) {
                console.error('Error creating user with Google data:', err);
                return res.status(500).json({ error: 'Failed to create user' });
              }
              
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
          );
        }
      }
    );
  } catch (error) {
    console.error('Google authentication error:', error);
    res.status(500).json({ error: 'Failed to authenticate with Google' });
  }
});

// Update your CORS middleware configuration
const corsOptions = {
  origin: [
    'https://splitta1.vercel.app',
    'http://localhost:3000' // For local development
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
// User Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }
    
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      
      if (results.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      const user = results[0];
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
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/api/users/me', authenticateToken, (req, res) => {
  db.query('SELECT id, fullName, email FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(results[0]);
  });
});

// ROOMMATE ROUTES

// Get all roommates
app.get('/api/roommates', authenticateToken, (req, res) => {
  db.query('SELECT * FROM roommates WHERE userId = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// Add a new roommate
app.post('/api/roommates', authenticateToken, (req, res) => {
  const { name } = req.body;
  const userId = req.user.id;
  
  if (!name || name.trim() === '') {
    return res.status(400).json({ error: 'Roommate name is required' });
  }
  
  db.query('INSERT INTO roommates (name, userId) VALUES (?, ?)', [name, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    const id = result.insertId;
    res.status(201).json({ id, name, userId });
  });
});

// Remove a roommate
app.delete('/api/roommates/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.id;
  
  db.query('SELECT * FROM roommates WHERE id = ? AND userId = ?', [id, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Roommate not found or not authorized' });
    }
    
    db.query('DELETE FROM roommates WHERE id = ?', [id], (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ message: 'Roommate deleted successfully' });
    });
  });
});

// EXPENSE ROUTES

// Get all expenses
app.get('/api/expenses', authenticateToken, (req, res) => {
  db.query('SELECT * FROM expenses WHERE userId = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    // Parse the splitAmong JSON string
    const expenses = results.map(expense => ({
      ...expense,
      splitAmong: expense.splitAmong ? JSON.parse(expense.splitAmong) : []
    }));
    
    res.json(expenses);
  });
});

// Add a new expense
app.post('/api/expenses', authenticateToken, (req, res) => {
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
    return res.status(400).json({ error: 'Please select at least one person to split with' });
  }

  db.query('SELECT * FROM roommates WHERE id = ? AND userId = ?', [paidBy, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(400).json({ error: 'Invalid roommate selected' });
    }
    
    // Verify all splitAmong roommates belong to the user
    db.query(
      'SELECT COUNT(*) as count FROM roommates WHERE id IN (?) AND userId = ?',
      [splitAmong, userId],
      (err, results) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        if (results[0].count !== splitAmong.length) {
          return res.status(400).json({ error: 'Invalid roommates selected for splitting' });
        }
        
        db.query(
          'INSERT INTO expenses (description, amount, paidBy, date, userId, splitAmong) VALUES (?, ?, ?, ?, ?, ?)',
          [description, amount, paidBy, date, userId, JSON.stringify(splitAmong)],
          (err, result) => {
            if (err) {
              return res.status(500).json({ error: err.message });
            }
            
            const id = result.insertId;
            res.status(201).json({ 
              id, 
              description, 
              amount, 
              paidBy, 
              date, 
              userId,
              splitAmong 
            });
          }
        );
      }
    );
  });
});

// Delete an expense
app.delete('/api/expenses/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.id;
  
  db.query('SELECT * FROM expenses WHERE id = ? AND userId = ?', [id, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Expense not found or not authorized' });
    }
    
    db.query('DELETE FROM expenses WHERE id = ?', [id], (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ message: 'Expense deleted successfully' });
    });
  });
});

// SETTLEMENT ROUTES

// Get all settlements
app.get('/api/settlements', authenticateToken, (req, res) => {
  db.query('SELECT * FROM settlements WHERE userId = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// Add a new settlement
app.post('/api/settlements', authenticateToken, (req, res) => {
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
  
  db.query(
    'SELECT * FROM roommates WHERE id IN (?, ?) AND userId = ?',
    [fromId, toId, userId],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      if (results.length !== 2) {
        return res.status(400).json({ error: 'Invalid roommates selected' });
      }
      
      db.query(
        'INSERT INTO settlements (fromId, toId, amount, date, userId) VALUES (?, ?, ?, ?, ?)',
        [fromId, toId, amount, date, userId],
        (err, result) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          
          const id = result.insertId;
          res.status(201).json({ id, fromId, toId, amount, date, userId });
        }
      );
    }
  );
});

// Delete a settlement
app.delete('/api/settlements/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.id;
  
  db.query('SELECT * FROM settlements WHERE id = ? AND userId = ?', [id, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Settlement not found or not authorized' });
    }
    
    db.query('DELETE FROM settlements WHERE id = ?', [id], (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ message: 'Settlement deleted successfully' });
    });
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
