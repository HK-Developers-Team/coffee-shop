const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.json({
          success: false,
          message: 'Token is not valid',
        });
      }
      if (decoded.role === 3) {
        req.userData = decoded;
        return next();
      }
      return res.json({
        success: false,
        message: 'You are not administrator',
      });
    });
  } else {
    return res.json({
      success: false,
      message: 'Auth token is not supplied',
    });
  }
  return 0;
};
