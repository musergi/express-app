const LocalStrategy = require('passport-local').Strategy;
const radclient = require('radclient');

const localConfig = 
{
    usernameField: 'username',
    passwordField: 'password',
    session: false 
}

async function radiusAuth(username, password, cb)
{
    const packet = {
        code: 'Access-Request',
        secret: 'testing123',
        identifier: 123,
        attributes: [
            ['User-Name', username],
            ['User-Password', password]
        ]
    };
    const options = {
        host: 'localhost',
        port: '1812',
        timeout: 2000,
        retries: 3
    }
    radclient(packet, options, (err, response) => {
        if (err)
            console.log('Radius error: %s', err);
        if (response.code == 'Access-Accept')
            return cb(null, { username: username, provider: 'RADIUS' });
        return cb(null, false);
    });
}

function RadiusStrategy()
{
    return new LocalStrategy(localConfig, radiusAuth);
}

module.exports = RadiusStrategy;