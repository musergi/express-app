const fs = require('fs');
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const GitHubStrategy = require('passport-github').Strategy;
const scrypt = require('scrypt-pbkdf');

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

/**
 * Generic file user fetcher factory.
 * 
 * Generates a function that get the user specified as the subject in the token
 * from the filepath passed as a parameter.
 * 
 * @param filepath  filepath containing the JSON database
 * 
 * @returns the authentication function for the JwtStrategy
 */
const fileFetcher = (filepath) => {
	return (payload, done) => {
		fs.readFile(filepath, async (err, data) => {
			data = JSON.parse(data);
			if(!data[payload.sub]) {
				done(null, false);
			}
			done(null, data[payload.sub]);
		});
	};
};

const createUserFromProfile = (filepath) => {
	return (accessToken, refreshToken, profile, done) => {
		fs.readFile(filepath, async (err, data) => {
			data = JSON.parse(data);
			if (!data[profile.username]) {
				data[profile.username] = profile;
				fs.writeFileSync(filepath, data);
			}
			done(null, profile);
		});
	};
};

const fileLocalStrategy = (config, filepath) => new LocalStrategy(config,
		fileAuthentication(filepath));

const fileJwtStrategy = (config, filepath) => new JwtStrategy(config,
		fileFetcher(filepath));

const fileGithubStrategy = (config, filepath) => new GitHubStrategy(config,
		createUserFromProfile(filepath));

module.exports = {fileLocalStrategy, fileJwtStrategy, fileGithubStrategy};