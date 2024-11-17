const express = require('express');
const crypto = require('crypto');
const { open } = require('sqlite');
require('dotenv').config();
const cors = require('cors');
const sqlite3 = require('sqlite3');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

let db = null;
const databasePath = path.join(__dirname, 'user.db');
const jwtSecret = crypto.randomBytes(64).toString('hex');


const app = express();
app.use(express.json());

app.use(cors({
    origin: 'http://localhost:3000',
}));

const createTables = async () => {
    try {
        await db.exec(`
            CREATE TABLE IF NOT EXISTS userDetails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS todo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task TEXT NOT NULL,
                status VARCHAR(255) NOT NULL,
                userId INTEGER NOT NULL
            )
        `);

        console.log('Tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
        throw new Error('Database initialization failed');
    }
};

const initializeDbAndServer = async () => {
    try {
        db = await open({
            filename: databasePath,
            driver: sqlite3.Database,
        });

        await createTables();
        app.listen(4000, () => console.log('Server is running on: http://localhost:4000'));
    } catch (e) {
        console.error(`DB Error: ${e.message}`);
        process.exit(1);
    }
};

initializeDbAndServer();

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

// Helper function to validate required fields
const validateFields = (fields) => {
    return fields.every(field => field !== undefined && field !== null && field !== '');
};

// Routes
app.post('/login', async (req, res) => {
    const { name, password } = req.body;
    if (!validateFields([name, password])) {
        return res.status(400).json({ error: 'Invalid request: Missing username or password' });
    }
    try {
        const query = `SELECT * FROM userDetails WHERE username = ?`;
        const user = await db.get(query, [name]);
        console.log('User fetched:', user);

        if (user && await bcrypt.compare(password, user.password)) {
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

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!validateFields([username, email, password])) {
        return res.status(400).json({ error: 'Invalid request: Missing username, email, or password' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const selectUserQuery = `SELECT username FROM userDetails WHERE username = ? OR email = ?`;
        const dbUser = await db.get(selectUserQuery, [username, email]);

        if (!dbUser) {
            const newRegisterQuery = `INSERT INTO userDetails(username, email, password) VALUES (?, ?, ?)`;
            await db.run(newRegisterQuery, [username, email, hashedPassword]);
            res.status(200).json({ message: 'New user registered successfully' });
        } else {
            res.status(400).json({ error: 'User already exists' });
        }
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

app.get('/userDetails', async (req, res) => {
    try {
        const allUsersQuery = `SELECT * FROM userDetails`;
        const users = await db.all(allUsersQuery);
        res.status(200).json(users);
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

app.post('/todoPost/:user', authenticateToken, async (req, res) => {
    const user = req.params.user;
    const { task, status } = req.body;
    if (!validateFields([task, status])) {
        return res.status(400).json({ error: 'Invalid request: Missing task or status' });
    }
    try {
        const addTodoQuery = `INSERT INTO todo (task, status, userId) VALUES(?, ?, ?)`;
        const result = await db.run(addTodoQuery, [task, status, user]);
        res.status(200).json({ message: 'Todo added successfully', id: result.lastID });
    } catch (error) {
        console.error('Error adding todo:', error);
        res.status(500).json({ error: 'Failed to add todo' });
    }
});

app.get('/todoList/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const getTodoListQuery = `SELECT * FROM todo WHERE userId = ?`;
        const todos = await db.all(getTodoListQuery, [userId]);
        res.status(200).json(todos);
    } catch (error) {
        console.error('Error fetching todo list:', error);
        res.status(500).json({ error: 'Failed to fetch todo list' });
    }
});
