const express = require('express');
const crypto = require('crypto');
require('dotenv').config();
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');

// Database initialization
const databasePath = process.env.DATABASE_PATH || path.join(__dirname, 'user.db');
const jwtSecret = process.env.JWT_SECRET || 'fallback_secret';
const db = new Database(databasePath, { verbose: console.log });

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000' }));

// Create tables
const createTables = () => {
    try {
        db.exec(`
            CREATE TABLE IF NOT EXISTS userDetails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            );
        `);
        db.exec(`
            CREATE TABLE IF NOT EXISTS todo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task TEXT NOT NULL,
                status VARCHAR(255) NOT NULL,
                userId INTEGER NOT NULL
            );
        `);
        console.log('Tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
        throw new Error('Database initialization failed');
    }
};

// Initialize database and server
createTables();
app.listen(4000, () => console.log('Server is running on: http://localhost:4000'));

// Helper function to validate required fields
const validateFields = (fields) => {
    return fields.every(field => field !== undefined && field !== null && field !== '');
};

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Welcome to the API' });
});

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// User Registration
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    if (!validateFields([username, email, password])) {
        return res.status(400).json({ error: 'Invalid request: Missing username, email, or password' });
    }
    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const selectUserQuery = `SELECT username FROM userDetails WHERE username = ? OR email = ?`;
        const dbUser = db.prepare(selectUserQuery).get(username, email);

        if (!dbUser) {
            const newRegisterQuery = `INSERT INTO userDetails(username, email, password) VALUES (?, ?, ?)`;
            db.prepare(newRegisterQuery).run(username, email, hashedPassword);
            res.status(200).json({ message: 'New user registered successfully' });
        } else {
            res.status(400).json({ error: 'User already exists' });
        }
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// User Login
app.post('/login', (req, res) => {
    const { name, password } = req.body;
    if (!validateFields([name, password])) {
        return res.status(400).json({ error: 'Invalid request: Missing username or password' });
    }
    try {
        const query = `SELECT * FROM userDetails WHERE username = ?`;
        const user = db.prepare(query).get(name);
        console.log('User fetched:', user);

        if (user && bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
            res.status(200).json({ message: 'Login successful', token });
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Fetch User Details
app.get('/userDetails', (req, res) => {
    try {
        const allUsersQuery = `SELECT * FROM userDetails`;
        const users = db.prepare(allUsersQuery).all();
        res.status(200).json(users);
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

// Add Todo
app.post('/todoPost/:user', authenticateToken, (req, res) => {
    const user = req.params.user;
    const { task, status } = req.body;
    if (!validateFields([task, status])) {
        return res.status(400).json({ error: 'Invalid request: Missing task or status' });
    }
    try {
        const addTodoQuery = `INSERT INTO todo (task, status, userId) VALUES(?, ?, ?)`;
        const result = db.prepare(addTodoQuery).run(task, status, user);
        res.status(200).json({ message: 'Todo added successfully', id: result.lastInsertRowid });
    } catch (error) {
        console.error('Error adding todo:', error);
        res.status(500).json({ error: 'Failed to add todo' });
    }
});

// Fetch Todo List
app.get('/todoList/:userId', authenticateToken, (req, res) => {
    const userId = req.params.userId;
    try {
        const getTodoListQuery = `SELECT * FROM todo WHERE userId = ?`;
        const todos = db.prepare(getTodoListQuery).all(userId);
        res.status(200).json(todos);
    } catch (error) {
        console.error('Error fetching todo list:', error);
        res.status(500).json({ error: 'Failed to fetch todo list' });
    }
});

module.exports = app;
