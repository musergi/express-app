const fs = require('fs')
const express = require('express')
const http = require('http')
const https = require('https')
const logger = require('morgan')
const passport = require('passport')
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16)
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const scrypt = require('scrypt-pbkdf')
const strategies = require('./strategies');
const dotenv = require('dotenv');

function extractFromCookie(req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['token'];
  }
  return token;
}

dotenv.config()

const options = {
  port: 3000,
  dbFile: process.env.DB_FILE,
  localStrategy: {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  jwtStrategy: {
    jwtFromRequest: extractFromCookie,
    secretOrKey: jwtSecret,
    issuer: 'localhost:3000',
    audience: 'localhost:3000'
  },
  githubStrategy: {
    clientID: process.env.GITHUB_OAUTH_CLIENT_ID,
    clientSecret: process.env.GITHUB_OAUTH_SECRET,
    callbackURL: "https://localhost:3000/oauth/github/callback"
  },
  server: {
    key: fs.readFileSync(__dirname + '/cert/server.key'),
    cert: fs.readFileSync(__dirname + '/cert/server.crt')
  }
}

const app = express()
app.use(logger('dev'))
app.use(cookieParser())

passport.use('local', strategies.fileLocalStrategy(options.localStrategy, options.dbFile));
passport.use('jwt', strategies.fileJwtStrategy(options.jwtStrategy, options.dbFile));
passport.use('github', strategies.fileGithubStrategy(options.githubStrategy, options.dbFile));


passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.use(express.urlencoded({ extended: true }))
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(passport.initialize())
app.use(passport.session());

app.get('/', passport.authenticate('jwt', { failureRedirect: '/login', session: false }),
  (req, res) => {
    res.send(`Hello ${req.user.username} your fortune: ${fortune.fortune()}`)
  }
)

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', session: false }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: 'user'
    }
    const token = jwt.sign(jwtClaims, jwtSecret)
    res.cookie('token', token, { maxAge: 900000, secure: true })
    res.redirect('/');
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/oauth/github', passport.authenticate('github'));
app.get('/oauth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login'}),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: 'user'
    }
    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie('token', token, { maxAge: 900000, secure: true })
    res.redirect('/');
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
);

app.get('/logout',
  (req, res) => {
    res.clearCookie('token')
    res.redirect('/login')
  }
)

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

var server = https.createServer(options.server, app);

server.listen(options.port, () => {
  console.log(`Example app listening at https://localhost:${options.port}`)
})
