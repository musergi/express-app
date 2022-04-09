const fs = require('fs');
const express = require('express');
const https = require('https');
const logger = require('morgan');
const passport = require('passport');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const strategies = require('./strategies');
const controller = require('./controller.js');
const util = require('./util.js');

dotenv.config();

const options = {
  port: 3000,
  dbFile: process.env.DB_FILE,
  localStrategy: {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  jwtStrategy: {
    jwtFromRequest: util.cookieExtractor,
    secretOrKey: require('crypto').randomBytes(16),
    issuer: 'localhost:3000',
    audience: 'localhost:3000'
  },
  githubStrategy: {
    clientID: process.env.GITHUB_OAUTH_CLIENT_ID,
    clientSecret: process.env.GITHUB_OAUTH_SECRET,
    callbackURL: "https://localhost:3000/oauth/github/callback",
    session: false
  },
  server: {
    key: fs.readFileSync(__dirname + '/cert/server.key'),
    cert: fs.readFileSync(__dirname + '/cert/server.crt')
  }
}

const app = express()

/* Set up passport startegies */
passport.use('local', strategies.fileLocalStrategy(options.localStrategy, options.dbFile));
passport.use('jwt', strategies.fileJwtStrategy(options.jwtStrategy, options.dbFile));
passport.use('github', strategies.fileGithubStrategy(options.githubStrategy, options.dbFile));

/* Create different authentications */
const localAuth = passport.authenticate('local', { failureRedirect: '/login', session: false });
const jwtAuth = passport.authenticate('jwt', { failureRedirect: '/login', session: false });
const githubAuth = passport.authenticate('github', { failureRedirect: '/login', session: false });

/* Add middleware to application */
app.use(logger('dev'))
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))
app.use(passport.initialize())
app.use(util.errorHandler);

/* Configure routes */
app.get('/', jwtAuth, controller.index);
app.get('/login', controller.loginPage);
app.get('/oauth/github', githubAuth);

const tokenController = new controller.TokenController(options.jwtStrategy.secretOrKey);
app.post('/login', localAuth, tokenController.createToken.bind(tokenController));
app.get('/oauth/github/callback', githubAuth, tokenController.createToken.bind(tokenController)); 
app.get('/logout', tokenController.resetToken.bind(tokenController));

/* Start server */
const server = https.createServer(options.server, app);
server.listen(options.port, () => {
  console.log(`Example app listening at https://localhost:${options.port}`)
})
