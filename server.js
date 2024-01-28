const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Change this line
const { Pool } = require('pg');

const app = express();
const port = 3000;

const pool = new Pool({
  user: 'your_db_user',
  host: 'your_db_host',
  database: 'your_db_name',
  password: 'your_db_password',
  port: 5432,
});

app.use(express.json());

// Middleware to secure routes with JWT
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'your_secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Route to create a new user
app.post('/create-user', async (req, res) => {
  const { usr_name, usr_email, usr_password } = req.body;

  // Hash and salt the password using bcryptjs
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(usr_password, saltRounds); // Change this line

  // Insert user into the database
  const result = await pool.query(
    'INSERT INTO users (usr_name, usr_email, usr_passwordhash) VALUES ($1, $2, $3) RETURNING *',
    [usr_name, usr_email, hashedPassword]
  );

  res.status(201).json({ message: 'User created successfully', user: result.rows[0] });
});

// Route to login and get JWT and refresh token
app.post('/login', async (req, res) => {
  const { usr_email, usr_password } = req.body;

  // Fetch user from the database
  const result = await pool.query('SELECT * FROM users WHERE usr_email = $1', [usr_email]);
  const user = result.rows[0];

  // Check if user exists and password is correct
  if (!user || !(await bcrypt.compare(usr_password, user.usr_passwordhash))) { // Change this line
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  // Generate JWT
  const accessToken = jwt.sign({ usr_id: user.usr_id, usr_email: user.usr_email }, 'your_secret_key', { expiresIn: '15m' });

  // You can store refresh tokens in the database if needed
  const refreshToken = jwt.sign({ usr_id: user.usr_id, usr_email: user.usr_email }, 'your_refresh_secret_key');

  res.json({ accessToken, refreshToken });
});

// Secure route example
app.get('/secure-route', authenticateToken, (req, res) => {
  res.json({ message: 'This is a secure route', user: req.user });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
