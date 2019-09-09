const router = require('express').Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require
const { loginValidation, registerValidation } = require('../validation');

router.post('/register', async (req,res) => {

    const { username, password, email } = req.body;

    const { error } = registerValidation(req.body)
    if(error) return res.status(400).send(error.details[0].message)

    const existUsername = await User.findOne({ username });
    if(existUsername) return res.status(401).send('Username already exists')

    const salt = await bcrypt.genSalt(8);
    const hashPass = await bcrypt.hash(password, salt)

    const user = new User({
        username,
        password: hashPass,
        email
    })

    try {
        const saveUser = await user.save();
        return res.send(saveUser)
    } catch (error) {
        return res.status(400).send(error)
    }
})

module.exports = router;
