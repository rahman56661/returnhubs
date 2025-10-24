const express = require('express');
const User = require('../models/User');
const router = express.Router();

router.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

router.post('/forgot-password', async (req, res) => {
    const email = req.body.email;

    try {
        const user = await User.findOne({ email });

        if (user) {
            console.log(`Password reset link sent to ${email}`);
            res.send('Password reset link sent to your email!');
        } else {
            res.status(404).send('Email not found');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

router.get('/signup', (req, res) => {
    res.render('signup');
});

router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).send('Please provide all required fields.');
    }

    try {
        const newUser = new User({ username, email, password });
        await newUser.save();
        res.send('Signup successful!');
    } catch (error) {
        console.error('Error saving user data:', error);

        if (error.code === 11000) {
            return res.status(400).send('Email already in use');
        }

        if (error.name === 'ValidationError') {
            return res.status(400).send('Validation error: ' + error.message);
        }

        return res.status(500).send('Error saving user data');
    }
});

module.exports = router;