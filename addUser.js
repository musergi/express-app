const fs = require('fs');
const scrypt = require('scrypt-pbkdf');
const dbFile = 'users.json'

function buffer2hex(buffer) {
  return Buffer.from(buffer).toString('hex');
}

async function createRecord(username, password) {
  const salt = scrypt.salt();
  const derivedKeyLength = 32;
  const key = await scrypt.scrypt(password, salt, derivedKeyLength);
  return {
    username: username,
    salt: buffer2hex(salt),
    key: buffer2hex(key)
  };
}

createRecord('walrus', 'walrus').then((record) => {
  let users = JSON.parse(fs.readFileSync(dbFile));
  users.push(record);
  fs.writeFileSync(dbFile, JSON.stringify(users));
})
