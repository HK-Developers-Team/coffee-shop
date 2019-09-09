const express = require('express');

const router = express.Router();

const dotenv = require('dotenv');

const bcrypt = require('bcryptjs');

const jwt = require('jsonwebtoken');

const connection = require('../mysql');

const authentication = require('../authentication');

const adminAuthorization = require('../AdminAuthorization');

dotenv.config({ path: '../config.env' });

router.get('/', adminAuthorization, (req, res) => {
  const query = 'SELECT * FROM user';
  connection.query(query, (err, results) => {
    if (err) {
      return res.status(403).json({ err });
    }
    if (!err) {
      return res.status(200).json({
        message: 'Success',
        data: results,
      });
    }
  });
});

router.get('/:username', authentication, (req, res) => {
  const query = `SELECT * FROM user WHERE user.username = '${req.params.username}'`;
  connection.query(query, (err, result) => {
    if (err) {
      return res.status(403).json({ err });
    }
    if (!err) {
      return res.status(200).json({
        message: 'Success',
        data: result,
      });
    }
  });
});

router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  const query = 'INSERT INTO user (username, password, email) VALUES (?, ?, ?)';
  bcrypt.genSalt(10, (errSalt, salt) => {
    bcrypt.hash(password, salt, (errHash, hash) => {
      if (!errHash) {
        connection.query(query, [username, hash, email], (err, result) => {
          if (err) {
            return res.status(403).json({ err });
          }
          if (!err) {
            return res.status(200).json({
              message: 'Success',
              data: result,
            });
          }
        });
      }
    });
  });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM user WHERE user.username = ?';
  connection.query(query, [username], (err, result) => {
    if (err) {
      return res.status(403).json({ err });
    }
    if (!err) {
      if (result.length) {
        bcrypt.compare(password, result[0].password).then((isMatch) => {
          if (isMatch) {
            const user = {
              id: result[0].id,
              username: result[0].username,
              role: result[0].role,
            };
            const token = jwt.sign(user, process.env.JWT_SECRET, {
              expiresIn: 60 * 60 * 24,
            });
            return res.status(200).json({
              success: true,
              token,
            });
          }
        });
      } else {
        return res.send('Error');
      }
      return 0;
    }
  });
});

module.exports = router;
