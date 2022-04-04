const fs = require('fs')
const express = require('express')
const https = require('https')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16)
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const fortune = require('fortune-teller')
const scrypt = require('scrypt-pbkdf')

function extractFromCookie(req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['token'];
  }
  return token;
}

const options = {
  port: 3000,
  dbFile: 'users.json',
  jwtStrategy: {
    jwtFromRequest: extractFromCookie,
    secretOrKey: jwtSecret,
    issuer: 'localhost:3000',
    audience: 'localhost:3000'
  },
  server: {
    key: fs.readFileSync(__dirname + '/cert/server.key'),
    cert: fs.readFileSync(__dirname + '/cert/server.crt')
  }
}

const app = express()
app.use(logger('dev'))
app.use(cookieParser())

async function validate(user, password) {
  if (user == null) {
    return false;
  }
  const salt = Buffer.from(user['salt'], 'hex');
  const key = Buffer.from(user['key'], 'hex');
  const testedKey = Buffer.from(await scrypt.scrypt(password, salt, 32));
  const matches = Buffer.compare(key, testedKey) == 0;
  if (!matches) {
    return false;
  }
  return user;
}

passport.use('local', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  function (username, password, done) {
    fs.readFile(options.dbFile, async (err, data) => {
      data = JSON.parse(data);
      const user = data[username];
      const validUser = await validate(user, password);
      done(null, validUser);
    });
  }
))

passport.use('jwt', new JwtStrategy(options.jwtStrategy, (payload, done) => {
  if (payload.sub == 'walrus') {
    const user = { 
      username: 'walrus',
      description: 'the only user that deserves to contact the fortune teller'
    }
    return done(null, user);
  }
  return (null, false);
}))


app.use(express.urlencoded({ extended: true }))
app.use(passport.initialize())

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
