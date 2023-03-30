console.log("Password: ${process.env.DB_PASSWORD}");
// Importing necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs@2.3.0');
const dotenv = require('dotenv');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

// Loads environment variables from .env file
dotenv.config();

// Creating an express application
const app = express();

// Setting the port number to either the value in the environment variable or 3000
const port = process.env.PORT || 3000;

// Creating a new connection pool for PostgreSQL database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  user: 'postgres',
  password: 'process.env.DB_PASSWORD', // Make sure this is a string
  host: 'localhost',
  database: 'postgres',
  port: 5432,
});


// Connecting to the PostgreSQL database
pool.connect();

// Creating a rate limiter middleware to limit requests from the same IP address
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100
// });

// Adding a security header to the response object
// app.use((req, res, next) => {
//   res.setHeader("Content-Security-Policy", "script-src 'self' 'unsafe-inline'");
//   return next();
// });

// Adding a set of security middleware to the express app
app.use(helmet());

// Adding a rate limiter middleware to the express app
app.use(limiter);

// Setting the view engine to EJS and the views directory to ./views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// serves up static files from the public folder. Anything in public/ will just be served up as the file it is
app.use(express.static(path.join(__dirname, 'public')));

// Takes the raw requests and turns them into usable properties on req.body
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
  secret: 'my-very-strong-secret-key-that-nobody-can-guess',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
  }));

// Handling GET request to the /success endpoint
app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'success.html'));
});

// Handling GET request to the /login endpoint
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Handling POST request to the /login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Sanitize user input to prevent SQL injection attacks
    // const sanitizedUsername = username.replace(/['";]/g, '');
    // const sanitizedPassword = password.replace(/['";]/g, '');
  
    // Sanitize user input to prevent SQL injection attacks
    if (!sanitizedUsername || !sanitizedPassword) {
      res.status(400).send('Username and password are required');
      return;
    }
  
    try {
      const result = await pool.query(query);
  
      if (result.rows.length === 0) {
        res.status(401).send('Invalid username or password');
      } else {
        const match = await bcrypt.compare(sanitizedPassword, result.rows[0].password);
  
        if (match) {
          res.redirect('/success');
        } else {
          res.status(401).send('Invalid username or password');
        }
      }
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal server error');
    }
  });
  

// Handling GET request to the /signup endpoint
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Handling POST request to the /signup endpoint
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const username1 = "'; DROP TABLE users; --";


    if (!username || !password) {
        res.status(400).send('Username and password are required');
        return;
    }

    if (password.length < 6) {
        res.status(400).send('Password must be at least 6 characters');
        return;
    }

    // Unsanitized user input that won't prevent XSS attacks
    const sanitizeHtml = require('sanitize-html');
    const sanitizedUsername = username;
    const sanitizedPassword = password;
    

    // Check if user already exists
    const userExistsQuery = {
        query: 'SELECT * FROM users WHERE username = ${username}',
        values: [sanitizedUsername],
    };

    const userExists = await pool.query(userExistsQuery);

    if (userExists.rowCount > 0) {
        res.status(409).send('Username already exists');
        return;
    }

    // Insert new user
    const insertQuery = {
        text: 'INSERT INTO users (username, password) VALUES ($1, $2)',
        values: [sanitizedUsername, await bcrypt.hash(sanitizedPassword, 10)],
    };

    try {
        await pool.query(insertQuery);
        res.redirect('/success');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal server error');
    }
});


const server = app.listen(port, () => {
  console.log("App running on port ${port}");
  });
