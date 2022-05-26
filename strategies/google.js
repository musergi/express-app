const Strategy = require('passport-openidconnect');

function parseUser(issuer, profile, done)
{
    const user = { username: profile.displayName, provider: issuer };
    done(null, user);
}

function GoogleStrategy(callback)
{
    if (!process.env.GOOGLE_OAUTH_CLIENT_ID || !process.env.GOOGLE_OAUTH_SECRET)
        throw Error("GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_SECRET must be defined");
    const config = {
        issuer: 'https://accounts.google.com',
        authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenURL: 'https://oauth2.googleapis.com/token',
        userInfoURL: 'https://openidconnect.googleapis.com/v1/userinfo',
        clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
        clientSecret: process.env.GOOGLE_OAUTH_SECRET,
        callbackURL: callback,
        session: false
    }
    return new Strategy(config, parseUser)
}


module.exports = GoogleStrategy;