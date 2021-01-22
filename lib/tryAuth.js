const jwt = require('jsonwebtoken');
const { parse } = require('cookie');

const NOT_AUTHENTICATED = 'NOT_AUTH';

// if jwt is valid, then return decoded jwt. otherwise throw error.
const tryAuth = (request, config = {}, options = {}) => {
  const { cookieName, jwtSecretKey } = config;
  const { ignoreExp } = options;
  if (!cookieName) throw new Error('cookieName is required.');
  if (!jwtSecretKey) throw new Error('jwtSecretKey is required');
  
  try {
    const cookies = parse(request.headers.cookie || '');
    const token = cookies[cookieName];
    return jwt.verify(token, jwtSecretKey, { ignoreExpiration: !!ignoreExp });
  } catch (ex) {
    throw new Error(NOT_AUTHENTICATED);
  }
  
}

module.exports = tryAuth;