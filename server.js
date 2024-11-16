const express = require('express');
const crypto = require('crypto');
const { open } = require('sqlite');
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
    await db.exec(`
        CREATE TABLE IF NOT EXISTS userDetails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    `);

    await db.exec(`
        CREATE TABLE IF NOT EXISTS todo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            status VARCHAR(255) NOT NULL,
            userId VARCHAR(225) NOT NULL
        )
    `);

    console.log('Tables created successfully');
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
        console.log(`DB Error: ${e.message}`);
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

app.post('/', async (req, res) => {
    const { name, password } = req.body;
    try {
        const query = `SELECT * FROM userDetails WHERE username = ?`;
        const user = await db.get(query, [name]);

        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
            res.status(200).json({ message: 'Successfully logged in', token });
        } else {
            res.status(401).send({ error: 'Invalid username or password.' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Failed to authenticate user' });
    }
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const selectUserQuery = `SELECT username FROM userDetails WHERE username = ?`;
    const dbUser = await db.get(selectUserQuery, [username]);

    if (dbUser === undefined) {
        try {
            const newRegisterQuery = `INSERT INTO userDetails(username,email,password) VALUES (?,?,?)`;
            const result = await db.run(newRegisterQuery, [username, email, hashedPassword]);
            res.status(200).json({ message: 'New user registered successfully' });
        } catch (err) {
            res.status(400).json({ message: err.message });
        }
    } else {
        res.status(400).send({ message: 'User already exists' });
    }
});

app.get('/userDetails', async (req, res) => {
    try {
        const allUsersQuery = `SELECT * FROM userDetails`;
        const result = await db.all(allUsersQuery);
        res.status(200).send(result);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.delete('/delete', async (req, res) => {
    try {
        const deleteQuery = `DELETE FROM userDetails`;
        await db.run(deleteQuery);
        res.status(200).json({ message: "Successfully deleted data" });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.post('/todoPost/:user', authenticateToken, async (req, res) => {
    try {
        const user = req.params.user;
        const { task, status } = req.body;
        const addTodoQuery = `INSERT INTO todo (task, status, userId) VALUES(?, ?, ?)`;
        const result = await db.run(addTodoQuery, [task, status, user]);
        res.status(200).json({ message: 'Todo added successfully', todo: result });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.get('/todoList/:userId', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        const getTodoListQuery = `SELECT * FROM todo WHERE userId = ?`;
        const result = await db.all(getTodoListQuery, [userId]);
        res.status(200).json({ list: result });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.get('/todoList', authenticateToken, async (req, res) => {
    try {
        const getTodoListQuery = `SELECT * FROM todo`;
        const result = await db.all(getTodoListQuery);
        res.status(200).json({ list: result });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.put('/updateTodo/:id', authenticateToken, async (req, res) => {
    const id = req.params.id;
    const { task, status } = req.body;
    try {
        const updateTodoQuery = `UPDATE todo SET task = ?, status = ? WHERE id = ?`;
        await db.run(updateTodoQuery, [task, status, id]);
        res.status(200).json({ message: 'Todo updated successfully' });
    } catch (error) {
        console.error('Error updating todo:', error);
        res.status(500).json({ error: 'Failed to update todo' });
    }
});

app.delete('/deleteTodo/:id', authenticateToken, async (req, res) => {
    const id = req.params.id;
    try {
        const deleteTodoQuery = 'DELETE FROM todo WHERE id = ?';
        await db.run(deleteTodoQuery, [id]);
        res.status(200).json({ message: 'Todo deleted successfully' });
    } catch (error) {
        console.error('Error deleting todo:', error);
        res.status(500).json({ error: 'Failed to delete todo' });
    }
});
