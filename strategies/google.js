const Strategy = require('passport-google-oidc');

function parseUser(issuer, profile, done)
{
    console.log(issuer);
    console.log(profile);
    const user = { username: profile.displayName, provider: 'Google' };
    done(null, user);
}

function GoogleStrategy(callback)
{
    if (!process.env.GOOGLE_OAUTH_CLIENT_ID || !process.env.GOOGLE_OAUTH_SECRET)
        throw Error("GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_SECRET must be defined");
    const config = {
        clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
        clientSecret: process.env.GOOGLE_OAUTH_SECRET,
        callbackURL: callback,
        scope: ['profile'],
        session: false
    }
    return new Strategy(config, parseUser)
}


module.exports = GoogleStrategy;