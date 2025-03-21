import jwt from 'jsonwebtoken';

export const isLoggedIn = async (req, res, next) => {
  try {
    // 1. Ensure `cookie-parser` is used in your app
    let token = req.cookies?.token;

    // 2. If no token, deny access
    if (!token) {
      return res.status(401).json({
        message: 'Authentication failed. No token provided.',
        success: false,
      });
    }

    // 3. Verify the token
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'default_secret'
    );
    console.log('Decoded data: ', decoded);

    // 4. Attach user to request object
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Auth middleware failure:', err);

    // 5. Handle JWT errors
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        message: 'Invalid token',
        success: false,
      });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        message: 'Token expired',
        success: false,
      });
    }

    return res.status(500).json({
      message: 'Internal server error',
      success: false,
    });
  }
};
