const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Registration route
router.get('/register', authController.showRegisterForm);
router.post('/register', authController.register);

// Login route
router.get('/login', authController.showLoginForm);
router.post('/login', authController.login);

// Logout route
router.get('/logout', authController.logout);

// Reset password routes
router.get('/reset-password', authController.showResetPasswordForm);
router.post('/reset-password', authController.resetPassword);

// Forgot password routes
router.get('/forgot-password', authController.showForgotPasswordForm);
router.post('/forgot-password', authController.forgotPassword);

// Google login/signup routes
router.get('/auth/google', authController.googleLogin);
router.get('/auth/google/callback', authController.googleCallback);

module.exports = router;
