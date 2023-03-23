const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt'); // password hashing / salting library / [Sensitive Data Exposure / A02:2021-Cryptographic Failures]
const csrf = require('csurf'); // ANTI-CSRF [A01:2021 Broken Access Control] 
const cookieParser = require('cookie-parser');

const csrfProtection = csrf({ cookie: true });

const { body } = require('express-validator'); // nodejs sanitization package [A03:2021-Injection]

const app = express();
const port = 3000;

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

app.use(session({
  secret: '0GnJkPGgg0doBS2SqZ19JLZXzWNBDBMH',
  resave: false,
  saveUninitialized: false,
}));

const db = new sqlite3.Database('database.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the database.');
});

//index

app.get('/', (req, res) => {
  if (req.session.userId) {
    res.render('index');
  } else {
    res.redirect('login');
  }
});

// login

//ge
app.get('/login', csrfProtection, (req, res) => {       // [A01:2021 Broken Access]
  const errorMessage = null;
  res.render('login', { csrfToken: req.csrfToken(), errorMessage });
});

// post
app.post('/login', csrfProtection, [ // [A01:2021 Broken Access Control]

  body('username').trim().escape(), //sanitize username input [Cross-Site Scripting (XSS) Prevention / A03:2021 Injection]
  body('password').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention / A03:2021 Injection]

], (req, res) => {
  const { username, password } = req.body;
  var errorMessage = null;

  if (!username || !password) {

    res.status(400).render('login', { csrfToken: req.csrfToken(), errorMessage: 'All fields are required!!' });
    return;
  }

  // parameterised inputs [SQL Injection Prevention / A03:2021 Injection]
  db.get('SELECT id, username, password FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error(err.message);
      res.status(500).render('login', { csrfToken: req.csrfToken(), errorMessage: 'Internal Server Error' });
      return;
    }

    if (!row) {
      res.render('login', { csrfToken: req.csrfToken(), errorMessage: 'Internal Server Error' });

      // log failed login [A09:2021 Security Logging and Monitoring]
      db.run('INSERT INTO failed_login_logs (username) VALUES (?)', [username], (err) => {
        if (err) {
          console.error(err.message);
          res.status(500).render('login', { csrfToken: req.csrfToken(), errorMessage: 'Internal Server Error' });
        }
      });
      console.log('failed login attempt detected, logged in database!');
      return;
    }

    // compare generated hash from entered password against hash in password column in db
    bcrypt.compare(password, row.password, (err, result) => {
      if (err || !result) {
        res.status(500).render('login', { csrfToken: req.csrfToken(), errorMessage: 'Invalid password or username' });

        // log failed login [A09:2021 Security Logging and Monitoring]
        db.run('INSERT INTO failed_login_logs (username) VALUES (?)', [username], (err) => {
          if (err) {
            console.error(err.message);
            res.status(500).render('login', { csrfToken: req.csrfToken(), errorMessage: 'Internal Server Error' });
          }
        });
        console.log('failed login attempt detected, logged in database!');
        return;
      }

      req.session.userId = row.id;
      console.log(`${username} successfully logged in`);

      res.render('index', { user: row, csrfToken: req.csrfToken()} );
    });
  });
});

//register
//get
app.get('/register', csrfProtection, (req, res) => { // [A01:2021 Broken Access Control]
  const errorMessage = null;
  res.render('register', { csrfToken: req.csrfToken(), errorMessage });
});

//post
app.post('/register', csrfProtection, [ // [A01:2021 Broken Access Control]

  body('username').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention / A03:2021 Injection]
  body('password').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention / A03:2021 Injection]
  body('confirmPassword').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention / A03:2021 Injection]

], (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (!username || !password || !confirmPassword) {
    res.status(400).render('register', { csrfToken: req.csrfToken(), errorMessage: 'All fields are required !' });
    return;
  }

  if (password !== confirmPassword) {
    res.status(400).render('register', { csrfToken: req.csrfToken(), errorMessage: 'Passwords do not match !' });
    return;
  }

  // salt password 
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error(err.message);
      res.status(500).render('register', { csrfToken: req.csrfToken(), errorMessage: 'Internal Server Error !' });
      return;
    }

    // parameterised inputs [SQL Injection Prevention / A03:2021 Injection]
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err) => { // pass hash to database password column
      if (err) {
        console.error(err.message);
        res.status(500).render('register', { csrfToken: req.csrfToken(), errorMessage: 'Internal Server Error !' });
        return;
      }

      console.log(`${username} was successfully registered`);
      res.redirect('/');
    });
  });
});

//logout

app.post('/logout', csrfProtection, (req, res) => { // [A01:2021 Broken Access Control]
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/login');
  });
});

//start app
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});