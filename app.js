const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt'); // password hashing / salting library / [Secure Password Storage]

const { body } = require('express-validator'); // nodejs sanitization package

const app = express();
const port = 3000;

app.use (bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

app.use(session({
    secret: '0GnJkPGgg0doBS2SqZ19JLZXzWNBDBMH',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true, // enable secure sessions [Session Management]
    }
}));

const db = new sqlite3.Database('database.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the database.');
});

//index

app.get('/', (req, res) => {
    if(req.session.userId) {
        res.render('index');
    } else {
        res.redirect('login');
    }
});

// login

//get
app.get('/login', (req, res) => {
    res.render('login');
});

// post
app.post('/login', [

  body('username').trim().escape(), //sanitize username input [Cross-Site Scripting (XSS) Prevention]
  body('password').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention]

], (req,res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      res.render('login', { error: 'All fields are required' });
      return;
    }

    // parameterised inputs [SQL Injection Prevention]
    db.get('SELECT id, username, password FROM users WHERE username = ?', [username], (err, row) => { 
      if (err) {
        console.error(err.message);
        res.status(500).send('Internal server error')
        return;
      }

      if (!row) {
        res.render('login', {error: 'Invalid username or password'});
        return;
      }

      if (password !== row.password) {
        res.render('login', { error: 'Invalid username or password'});
        return;
      }

      req.session.userId = row.id;
      console.log(`${username} successfully logged in`);
      res.render('index', {user: row});
    });
});

//register
//get
app.get('/register', (req, res) => {
    res.render('register');
});

//post
app.post('/register', [

  body('username').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention]
  body('password').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention]
  body('confirmPassword').trim().escape(), // sanitize password input [Cross-Site Scripting (XSS) Prevention]
  
], (req, res) => {
    const { username, password, confirmPassword } = req.body;
    
    if (!username || !password || !confirmPassword) {
      res.status(400).send('All fields are required');
      return;
    }
  
    if (password !== confirmPassword) {
      res.status(400).send('Passwords do not match');
      return;
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if(err) {
        console.error(err.message);
        res.status(500).send('Internal server error');
        return;
      }
      
      // parameterised inputs [SQL Injection Prevention]
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err) => {
        if (err) {
          console.error(err.message);
          res.status(500).send('Internal server error');
          return;
        }

        console.log(`${username} was successfully registered`);
        res.redirect('/');
      });
    });
});

//logout

app.post('/logout', (req, res) => {

    req.session.destroy((err) => {
      if(err) {
      console.error(err);
    }
    res.redirect('login');
    });
  });

//start app
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});