const mysql = require('mysql');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'mern',
});

connection.connect((err) => {
  if (!err) {
    console.log('MySQL Database Connected Successfully!');
  } else {
    console.log('MySQL Error');
  }
});

module.exports = connection;
