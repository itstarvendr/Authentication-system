// Required dependencies
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./app/models/User');

// Import routes and controllers
const authRoutes = require('./app/routes/authRoutes');
const authController = require('./app/controllers/authController');

// Create an instance of the Express app
const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('app/public'));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
}));

// Connect to the database
mongoose.connect('mongodb://localhost:27017/authDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
}).then(() => {
  console.log('Connected to the database');
}).catch((error) => {
  console.error('Failed to connect to the database:', error);
  process.exit();
});

// Register routes
app.use('/', authRoutes);

// Start the server
app.listen(3000, () => {
  console.log('Authentication server is running on http://localhost:3000');
});
