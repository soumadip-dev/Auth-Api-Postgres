import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

const prisma = new PrismaClient();

// Controller for registering a user
const registerUser = async (req, res) => {
  // 1. Get data from request body
  const { name, email, password, phone } = req.body;

  // 2. Validate input fields
  if (!name || !email || !password || !phone) {
    return res.status(400).json({
      message: 'Please fill in all fields',
    });
  }

  try {
    // 3. Check if user already exists in the database
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      return res.status(409).json({
        message: 'User already exists',
      });
    }

    // 4. Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5. Generate a verification token
    const token = crypto.randomBytes(32).toString('hex');
    console.log(token);

    // 6. Create a new user in the database
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        phone,
        verificationToken: token,
      },
    });

    // 7. Configure email transporter
    const transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT, // Keep as it is, unless you face issues
      secure: false, // true for port 465, false for other ports
      auth: {
        user: process.env.MAILTRAP_USERNAME,
        pass: process.env.MAILTRAP_PASSWORD,
      },
    });

    // Email details
    const mailOptions = {
      from: process.env.MAILTRAP_SENDEREMAIL, // Sender email
      to: user.email, // Recipient email
      subject: 'Verify Your Email Address', // Subject
      text: `Hello ${user.name},\n\nPlease verify your email using the following link:\n\n${process.env.BASE_URL}/api/v1/users/verify/${token}\n\nThank you!`, // Plain text body
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 10px; max-width: 600px; margin: auto;">
          <h2 style="color: #333;">Hello <strong>${user.name}</strong>,</h2>
          <p style="font-size: 16px; color: #555;">Please verify your email by clicking the button below:</p>
          <p style="text-align: center;">
            <a href="${process.env.BASE_URL}/api/v1/users/verify/${token}" 
              style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px; display: inline-block;">
              Verify Email
            </a>
          </p>
          <p style="font-size: 14px; color: #777;">If you didn’t request this, you can ignore this email.</p>
          <p style="font-size: 14px; color: #777;">Thank you!</p>
        </div>
      `,
    };

    // Send verification email
    try {
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
    }

    // 8. Send success response to user
    res.status(201).json({
      message: 'User registered successfully.',
      success: true,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      message: 'Internal Server Error',
      error: err.message,
    });
  }
};

// Controller for user verification
const verifyUser = async (req, res) => {
  try {
    // 1. Get verification token from URL parameters
    const { token } = req.params;
    console.log(token);

    // 2. Validate if token exists
    if (!token) {
      return res.status(400).json({
        message: 'Invalid token',
      });
    }

    // 3. Find user based on token
    const user = await prisma.user.findFirst({
      where: { verificationToken: token },
    });

    // 4. If user not found, return error
    if (!user) {
      return res.status(404).json({
        message: 'User not found or already verified',
      });
    }

    // 5. Update user's `isVerified` status and remove `verificationToken`
    await prisma.user.update({
      where: { id: user.id },
      data: {
        isverified: true,
        verificationToken: null,
      },
    });

    // 6. Send success response to user
    res.status(200).json({
      message: 'Verification successful. You can now log in.',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      message: 'Internal Server Error',
      error: err.message,
    });
  }
};

// Controller for login
const login = async (req, res) => {
  try {
    // 1. Get user credentials from request body
    const { email, password } = req.body;

    // 2. Validate if email and password exist
    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password are required',
      });
    }

    // 3. Find user based on email
    const user = await prisma.user.findUnique({
      where: { email },
    });

    // 4. If user not found, return error
    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    // 5. Compare password with stored hash password in database
    const isValidPassword = await bcrypt.compare(password, user.password);

    // 6. If password is invalid, return error
    if (!isValidPassword) {
      return res.status(401).json({
        message: 'Invalid password',
      });
    }

    // 7. Check if user is verified or not
    if (!user.isverified) {
      return res.status(401).json({
        message: 'User is not verified',
      });
    }

    // 8. Generate JWT token
    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || 'default_secret', // Use env variable
      { expiresIn: '24h' }
    );

    // 9. Store JWT token in cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Secure in production
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    };
    res.cookie('token', token, cookieOptions);

    // 10. Send success response to user
    res.status(200).json({
      message: 'User logged in successfully',
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: 'Internal Server Error',
      error: error.message,
    });
  }
};

// Controller for profile
const getMe = async (req, res) => {
  try {
    // 1. Get user ID from middleware
    const userId = req.user.id;

    // 2. Find user without including the password
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        phone: true,
        email: true,
        role: true,
        isverified: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // 3. If user not found, return error
    if (!user) {
      return res.status(404).json({
        message: 'User not found',
        success: false,
      });
    }

    // 4. Send success response
    res.status(200).json({
      message: 'User profile retrieved successfully',
      success: true,
      user,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      message: 'Internal Server Error',
      success: false,
    });
  }
};

// Controller for logout user
const logout = async (req, res) => {
  try {
    // 1. Clear the cookie
    res.cookie('token', '', {});

    // 2. return success response
    res.status(200).json({
      message: 'Logged out successfully',
      success: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: 'Internal Server Error',
      success: false,
    });
  }
};

// Controller for forgot password
const forgotPassword = async (req, res) => {
  try {
    // 1. Get the email from the request body
    const { email } = req.body;

    // 2. Validate email
    if (!email) {
      return res.status(400).json({
        message: 'Email is required',
        success: false,
      });
    }

    // 3. Find user based on email
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // 4. Set reset token and expiry (10 minutes)
    const resetToken = crypto.randomBytes(32).toString('hex');

    // 5. Update the user in the database with reset token and expiry
    await prisma.user.update({
      where: { email },
      data: {
        passwordResetToken: resetToken,
        passwordResetExpires: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes expiry
      },
    });

    console.log('Generated Reset Token:', resetToken);

    // 6. Setup email transporter
    const transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT,
      secure: false,
      auth: {
        user: process.env.MAILTRAP_USERNAME,
        pass: process.env.MAILTRAP_PASSWORD,
      },
    });

    // 7. Create email content
    const resetLink = `${process.env.BASE_URL}/api/v1/users/reset-password/${resetToken}`;
    const mailOptions = {
      from: process.env.MAILTRAP_SENDEREMAIL || 'no-reply@example.com',
      to: user.email,
      subject: 'Reset Your Password',
      text: `Hello ${user.name},\n\nWe received a request to reset your password. Please use the link below to set a new password:\n\n${resetLink}\n\nThis link is valid for 10 minutes.\n\nIf you did not request this, please ignore this email.\n\nThank you!`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 10px; max-width: 600px; margin: auto;">
          <h2 style="color: #333;">Hello <strong>${user.name}</strong>,</h2>
          <p style="font-size: 16px; color: #555;">We received a request to reset your password.</p>
          <p style="font-size: 16px; color: #555;">Click the button below to reset your password:</p>
          <p style="text-align: center;">
            <a href="${resetLink}" 
              style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px; display: inline-block;">
              Reset Password
            </a>
          </p>
          <p style="font-size: 14px; color: #777;">This link will expire in 10 minutes.</p>
          <p style="font-size: 14px; color: #777;">If you did not request this, you can ignore this email.</p>
          <p style="font-size: 14px; color: #777;">Thank you!</p>
        </div>
      `,
    };

    // 8. Send the email
    await transporter.sendMail(mailOptions);

    res.status(200).json({
      success: true,
      message: 'Password reset email sent successfully',
    });
  } catch (error) {
    console.error('Error in forgotPassword:', error);
    return res.status(500).json({
      message: 'Internal Server Error',
      success: false,
    });
  }
};

// Controller for reset password
const resetPassword = async (req, res) => {
  try {
    // 1. Get the reset token from the params
    const { resetToken } = req.params;

    // 2. Get new password from body
    const { password } = req.body;

    // 3. Validate both token and password
    if (!resetToken || !password) {
      return res.status(400).json({
        message: 'Please provide both password and reset token',
        success: false,
      });
    }

    // 4. Find user with the provided reset token (Ensure token is not expired)
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: resetToken,
        passwordResetExpires: { gt: new Date() }, // Ensure token is still valid
      },
    });

    // 5. If user is not found, return an error
    if (!user) {
      return res.status(400).json({
        message: 'Invalid or expired password reset token',
        success: false,
      });
    }

    // 6. Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 7. Update the user's password and reset token fields
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null, // Reset token fields
        passwordResetExpires: null,
      },
    });

    // 8. Send success response
    res.status(200).json({
      message: 'Password reset successfully',
      success: true,
    });
  } catch (err) {
    console.error('Error in resetPassword:', err);
    return res.status(500).json({
      message: 'Internal Server Error',
      success: false,
    });
  }
};

export {
  forgotPassword,
  getMe,
  login,
  logout,
  registerUser,
  resetPassword,
  verifyUser,
};
