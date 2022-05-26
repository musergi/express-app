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
        host: '10.0.2.15',
        port: '3001',
        timeout: 2000,
        retries: 3
    }
    radclient(packet, options, (err, response) => {
        console.log(response);
        return cb(null, response);
    });
}

function RadiusStrategy()
{
    return new LocalStrategy(localConfig, radiusAuth);
}

module.exports = RadiusStrategy;