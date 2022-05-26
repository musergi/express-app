const Strategy = require('passport-github').Strategy;


function parseUser(accessToken, refreshToken, profile, done)
{
    const user = { username: profile.username, provider: profile.provider };
    done(null, user);
}

function GithubStrategy(callback)
{
    if (!process.env.GITHUB_OAUTH_CLIENT_ID || !process.env.GITHUB_OAUTH_SECRET)
        throw Error("GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_SECRET must be defined");
    const config = {
        clientID: process.env.GITHUB_OAUTH_CLIENT_ID,
        clientSecret: process.env.GITHUB_OAUTH_SECRET,
        callbackURL: callback,
        session: false
    }
    return new Strategy(config, parseUser)
}

module.exports = GithubStrategy;