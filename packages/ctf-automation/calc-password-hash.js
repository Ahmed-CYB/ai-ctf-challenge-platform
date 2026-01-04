import crypto from 'crypto';

// Guacamole password hashing: SHA-256(password + hex(salt))
const password = 'password123';
const salt = Buffer.from('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'hex');

const saltHex = salt.toString('hex');
const hash = crypto.createHash('sha256');
hash.update(password + saltHex);
const passwordHash = hash.digest();

console.log('Password:', password);
console.log('Salt (hex):', saltHex);
console.log('Hash (hex):', passwordHash.toString('hex'));
console.log('\nSQL UPDATE command:');
console.log(`UPDATE guacamole_user SET password_hash = unhex('${passwordHash.toString('hex')}') WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name='demo');`);
