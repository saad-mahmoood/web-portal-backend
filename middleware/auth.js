// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  try {
    let token;

    // Header: "Bearer <token>"
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // Optional: cookie fallback (if you set token in cookies)
    else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    // Verify token (jwt.verify throws if invalid/expired)
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_here');
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: 'Token is not valid.'
      });
    }

    // Get user from token payload
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Token is not valid. User not found.'
      });
    }

    // Normalize both possible property names in your DB/schema
    const isActive = (typeof user.isActive !== 'undefined') ? user.isActive : user.is_active;
    if (isActive === false) {
      return res.status(401).json({
        success: false,
        message: 'Account has been deactivated.'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error in authentication'
    });
  }
};

// Admin-only middleware
const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  return res.status(403).json({
    success: false,
    message: 'Access denied. Admin privileges required.'
  });
};

module.exports = { protect, admin };
