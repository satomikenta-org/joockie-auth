const jwt = require('jsonwebtoken');
const { serialize } = require('cookie');

const DEFAULT_EXPIRACY_IN_STR = '24h';
const DEFAULT_EXPIRACY = 60*60*24; 

// generate serialized cookie contains jwt.
const generateCookie = (payload, config = {}, options = {}) => {
  const { jwtSecretKey, expiresIn, cookieName } = config;
  const { httpOnly, secure, strict, maxAge, path } = options;
  if (!jwtSecretKey) throw new Error('jwtSecretKey is required.');
  if (!cookieName) throw new Error('cookieName is required.');

  const token = jwt.sign(payload, jwtSecretKey, { expiresIn: expiresIn || DEFAULT_EXPIRACY_IN_STR });
  
  return serialize(cookieName, token, { 
    httpOnly: !!httpOnly, 
    secure: !!secure, 
    strict: !!strict, 
    maxAge: maxAge || DEFAULT_EXPIRACY,
    path: path || '/'
  });
}

module.exports = generateCookie;