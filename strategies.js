const fs = require('fs');
const scrypt = require('scrypt-pbkdf')

const fileLocalStrategyConfig = {
	usernameField: 'username',
    passwordField: 'password',
    session: false
};

/**
 * Authenticates a user.
 * 
 * Validates that the user is not null, and then uses the passed plaintext
 * password matches the hash stored in the user object. The cryptographic
 * function used to hash is scrypt.
 * 
 * @param user      object containing at least the salt and hashed password
 * @param password  plaintext password
 * 
 * @returns false if the user failed to authenticate, the user otherwise
 */
const authenticate = async (user, password) => {
  if (user == null) {
    return false;
  }
  const salt = Buffer.from(user['salt'], 'hex');
  const key = Buffer.from(user['key'], 'hex');
  const testedKey = Buffer.from(await scrypt.scrypt(password, salt, 32));
  const matches = Buffer.compare(key, testedKey) == 0;
  if (!matches) {
    return false;
  }
  return user;
};

/**
 * Generic file authentication factory.
 * 
 * Generates a function that validates the passed user and password using the
 * database stored in JSON format. The parameter required to build it is the
 * filepath to read the database from.
 * 
 * @param filepath  filepath containing the JSON database
 * 
 * @returns the authentication function for the LocalStrategy
 */
const fileAuthentication = (filepath) => {
	return (username, password, done) => {
		fs.readFile(filepath, async (err, data) => {
	    data = JSON.parse(data);
	    const user = data[username];
	    const validUser = await authenticate(user, password);
	    done(null, validUser);
	  });
	};
};

const fileLocalStrategy = (config, filepath) => new LocalStrategy(config, fileAuthentication(filepath));

const fileJwtStrategy = (config, filepath) => new JwtStrategy(config, )

module.exports = {fileLocalStrategy}