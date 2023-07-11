const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Secret key for JWT (replace this with a securely stored secret in a production system)
const secretKey = 'your-secret-key';

// Show registration form
exports.showRegisterForm = (req, res) => {
  res.sendFile(__dirname + '/../views/register.html');
};

// Registration controller
exports.register = async (req, res) => {
  try {
    const { username, password, confirmPassword } = req.body;

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    // Check if username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user object
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    // Save the user to the database
    await newUser.save();

    // Respond with success message
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Show login form
exports.showLoginForm = (req, res) => {
  res.sendFile(__dirname + '/../views/login.html');
};

// Login controller
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ username });

    // Check if the user exists
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare the provided password with the stored password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // Check if the password is valid
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: user._id, username: user.username }, secretKey, {
      expiresIn: '1h',
    });

    // Set the token in the session
    req.session.token = token;

    // Redirect to the home page
    res.redirect('/home');
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Logout controller
exports.logout = (req, res) => {
  // Destroy the session and redirect to the login page
  req.session.destroy();
  res.redirect('/login');
};

// Show reset password form
exports.showResetPasswordForm = (req, res) => {
  res.sendFile(__dirname + '/../views/resetPassword.html');
};

// Reset password controller
exports.resetPassword = async (req, res) => {
  try {
    const { newPassword, confirmNewPassword } = req.body;

    // Check if new passwords match
    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Find the user by ID
    const user = await User.findById(req.session.userId);

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update the password
    user.password = hashedPassword;
    await user.save();

    // Respond with success message
    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Show forgot password form
exports.showForgotPasswordForm = (req, res) => {
  res.sendFile(__dirname + '/../views/forgotPassword.html');
};

// Forgot password controller
exports.forgotPassword = async (req, res) => {
  try {
    const { username } = req.body;

    // Find the user by username
    const user = await User.findOne({ username });

    // Check if the user exists
    if (!
