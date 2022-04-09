const fortune = require('fortune-teller');
const jwt = require('jsonwebtoken');

function index(req, res) {
  res.send(`Hello ${req.user.username} your fortune: ${fortune.fortune()}`)
}

function loginPage(req, res) {
  res.sendFile('login.html', { root: __dirname });
}

class TokenController {
  constructor(secret) {
    this.secret = secret;
  }

  createToken(req, res) {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: 'user'
    };
    const token = jwt.sign(jwtClaims, this.secret);
    res.cookie('token', token, { maxAge: 900000, secure: true });
    res.redirect('/');
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
    console.log(`Token secret (for verifying the signature): ${this.secret.toString('base64')}`);
  }

  resetToken(req, res) {
    res.clearCookie('token')
    res.redirect('/login')
  }
}

module.exports = { index, loginPage, TokenController };
