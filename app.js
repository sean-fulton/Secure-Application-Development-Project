const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use (bodyParser.urlencoded({ extended: true }));
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
    if(req.session.userId) {
        res.render('index');
    } else {
        res.redirect('login');
    }
});

// login

//get
app.get('/login', (req, res) => {
    const errorMessage = null;
    res.render('login', { errorMessage });
});

// post
app.post('/login', (req,res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).render('login', { errorMessage: 'All fields are required!!' });
      return;
    }

    db.get(`SELECT id, username, password FROM users WHERE username = '${username}'`, (err, row) => {
      if (err) {
        console.error(err.message);
        res.status(500).render('login', { errorMessage: 'Internal Server Error!!' });
        return;
      }

      if (!row) {
        res.status(500).render('login', { errorMessage: 'Internal Server Error!!' });
        return;
      }

      if (password !== row.password) {
        res.status(500).render('login', { errorMessage: 'Internal Server Error!!' });
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
    const errorMessage = null;
    res.render('register', { errorMessage });
});

//post
app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    
    if (!username || !password || !confirmPassword) {
      res.status(400).render('register', { errorMessage: 'All fields are required !!' });
      return;
    }
  
    if (password !== confirmPassword) {
      res.status(400).render('register', { errorMessage: 'Passwords do not match !!' });
      return;
    }
  
    db.run(`INSERT INTO users (username, password) VALUES ('${username}', '${password}')`, (err) => {
        if (err) {
          console.error(err.message);
          res.status(500).render('register', { errorMessage: 'Internal Server Error !!' });
          return;
        }

        console.log(`${username} was successfully registered`);
        res.redirect('/');
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