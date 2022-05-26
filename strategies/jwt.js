const JwtStrategy = require('passport-jwt').Strategy

const cookieExtractor = (req) => req && req.cookies ? req.cookies['token'] : null;

const defaultConfig = {
    jwtFromRequest: cookieExtractor,
    session: false // Check
}

function extractUser(payload, done)
{
    done(null, {'username': payload.sub})
}

function CustomJwtStrategy(secret, issuer)
{
    const customConfig = {
        secretOrKey: secret,
        issuer: issuer,
        audience: issuer
    }
    return new JwtStrategy({...defaultConfig, ...customConfig}, extractUser)
}

module.exports = CustomJwtStrategy;