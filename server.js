const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose')

const app = express();
app.use(cors());
app.use(express.json());

dotenv.config({ path: './config.env' });


mongoose.connect(process.env.DB, {useNewUrlParser: true}, (err) => {
    if(err) {
      throw err
    } else console.log('DB Connected')
})


const port = process.env.PORT;

app.get('/', (req, res) => res.json({ message: 'Hello from server' }));

app.use('/api/user', require('./routes/User'));

app.listen(port, (err) => {
  if(err) throw err;
  console.log(`Server running on port ${port}`);
});
