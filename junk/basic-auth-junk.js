const bcrypt = require('bcryptjs');
const AuthService = require('../auth/auth-service');

function requireAuth(req, res, next) {
  const authToken = req.get('authorization') || '';
  let basicToken;
  if (!authToken.toLowerCase().startsWith('basic ')) {
    return res.status(401).json({ error: 'Missing basic token' });
  } else {
    basicToken = authToken.slice('basic '.length, authToken.length);
  }

  //What is happening here?
  // const [tokenUserName, tokenPassword] = Buffer.from(basicToken, 'base64')
  //   .toString()
  //   .split(':');

  const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(
    basicToken
  );

  if (!tokenUserName || !tokenPassword) {
    return res.status(401).json({ error: 'Unauthorized request' });
  }

  // req.app
  //   .get('db')('thingful_users')
  //   .where({ user_name: tokenUserName })
  //   .first()
  //   .then((user) => {
  //     if (!user || user.password !== tokenPassword) {
  //       return res.status(401).json({ error: 'Unauthorized request' });
  //     }
  //     req.user = user;
  //     next();
  //   })
  //   .catch(next);

  AuthService.getUserWithUserName(req.app.get('db'), tokenUserName)
    .then((user) => {
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized request' });
      }
      req.user = user;
      next();
    })
    .catch(next);
}

module.exports = { requireAuth };
