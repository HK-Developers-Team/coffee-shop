const router = require('express').Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { loginValidation, registerValidation } = require('../validation');

dotenv.config({ path: '../config.env' });

router.post('/register', async (req, res) => {
	const { username, password, email } = req.body;

	const { error } = registerValidation(req.body);
	if (error) return res.status(400).send(error.details[0].message);

	const existUsername = await User.findOne({ username });
	if (existUsername) return res.status(401).send('Username already exists');

	const salt = await bcrypt.genSalt(8);
	const hashPass = await bcrypt.hash(password, salt);

	const user = new User({
		username,
		password: hashPass,
		email,
	});

	try {
		const saveUser = await user.save();
		return res.send(saveUser);
	} catch (error) {
		return res.status(400).send(error);
	}
});

router.post('/login', async (req, res) => {
	const { username, password } = req.body;

	const { error } = loginValidation(req.body);
	if (error) return res.status(400).send(error.details[0].message);

	const loginUser = await User.findOne({ username });
	if (!loginUser)
		return res.status(401).json({
			success: false,
			message: 'Username is not exists',
		});
	const validPass = await bcrypt.compare(password, loginUser.password);
	if (!validPass)
		return res.status(401).json({
			success: false,
			message: 'Password is wrong',
		});

	const token = jwt.sign({ _id: loginUser._id }, process.env.JWT_SECRET);
	res.header('auth-token', token).json({
		success: true,
		token,
	});
});

module.exports = router;
