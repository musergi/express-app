const fs = require('fs');
const express = require('express');
const https = require('https');
const logger = require('morgan');
const passport = require('passport');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const controller = require('./controller.js');
const util = require('./util.js');
const DatabaseStrategy = require('./strategies/database');
const JwtStrategy = require('./strategies/jwt');
const GithubStrategy = require('./strategies/github');
const GoogleStrategy = require('./strategies/google');
const RadiusStrategy = require('./strategies/radius');

dotenv.config();

const options = {
  port: 3000,
  dbFile: process.env.DB_FILE,
  jwtSecret: require('crypto').randomBytes(16),
  githubCallback: "https://localhost:3000/oauth/github/callback",
  googleCallback: "https://localhost:3000/openid/google/callback",
  server: {
    key: fs.readFileSync(__dirname + '/cert/server.key'),
    cert: fs.readFileSync(__dirname + '/cert/server.crt')
  }
}

const app = express()

/* Set up passport startegies */
// passport.use('local', DatabaseStrategy(options.dbFile));
passport.use('local', RadiusStrategy());
passport.use('jwt', JwtStrategy(options.jwtSecret, 'localhost:3000'));
passport.use('github', GithubStrategy(options.githubCallback));
passport.use('google', GoogleStrategy(options.googleCallback));

/* Create different authentications */
const localAuth = passport.authenticate('local', { failureRedirect: '/login', session: false });
const jwtAuth = passport.authenticate('jwt', { failureRedirect: '/login', session: false });
const githubAuth = passport.authenticate('github', { failureRedirect: '/login', session: false });
const googleAuth = passport.authenticate('google', { failureRedirect: '/login', session: false });

/* Add middleware to application */
app.use(logger('dev'))
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))
app.use(passport.initialize())
app.use(util.errorHandler);
app.use(require('express-session')( { secret: 'keyboard cat', resave: false, saveUninitialized: true, cookie: { secure: true }}))

/* Configure routes */
app.get('/', jwtAuth, controller.index);
app.get('/login', controller.loginPage);
app.get('/oauth/github', githubAuth);
app.get('/openid/google', googleAuth);

const tokenController = new controller.TokenController(options.jwtSecret);
app.post('/login', localAuth, tokenController.createToken.bind(tokenController));
app.get('/oauth/github/callback', githubAuth, tokenController.createToken.bind(tokenController));
app.get('/openid/google/callback', googleAuth, tokenController.createToken.bind(tokenController));
app.get('/logout', tokenController.resetToken.bind(tokenController));

/* Start server */
const server = https.createServer(options.server, app);
server.listen(options.port, () => {
  console.log(`Example app listening at https://localhost:${options.port}`)
})
