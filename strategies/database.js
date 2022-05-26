const fs = require('fs');
const LocalStrategy = require('passport-local').Strategy;
const scrypt = require('scrypt-pbkdf');

const localConfig = 
{
    usernameField: 'username',
    passwordField: 'password',
    session: false 
}

function DatabaseStrategy(filepath) {
    const dbAuth = new DatabaseAuthenticator(filepath);
    return new LocalStrategy(localConfig, dbAuth.authenticate.bind(dbAuth));
}

class DatabaseAuthenticator
{
    constructor(filepath)
    {
        this.filepath = filepath;
    }

    async authenticate(username, password, cb)
    {
        try
        {
            const data = await fs.promises.readFile(this.filepath);
            const parsed = JSON.parse(data);
            const user = parsed[username];
            const validUser = await this.validateUser(user, password);
            console.log('DatabaseStrategy: %s', validUser);
            return cb(null, validUser);
        }
        catch (err)
        {
            console.log(err);
        }
        return cb(null, false);
    }

    async validateUser(user, password)
    {
        if (user == null)
            return false;
        const salt = Buffer.from(user['salt'], 'hex');
        const key = Buffer.from(user['key'], 'hex');
        const testedKey = Buffer.from(await scrypt.scrypt(password, salt, 32));
        const matches = Buffer.compare(key, testedKey) == 0;
        if (!matches)
            return false;
        return { username: user['username'] };
    }
}

module.exports = DatabaseStrategy;