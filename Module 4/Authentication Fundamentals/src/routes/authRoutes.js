const express = require('express');
const bcrypt = require('bcryptjs');
const prisma = require('../db/prisma');

const router = express.Router();

const INVALID_CREDENTIALS = {
  error: {
    code: 'INVALID_CREDENTIALS',
    message: 'Invalid email or password',
  },
};

function validateRequiredString(value, fieldName) {
  if (typeof value !== 'string' || !value.trim()) {
    return {
      error: {
        code: 'VALIDATION_ERROR',
        message: `${fieldName} is required`,
      },
    };
  }

  return null;
}

router.post('/register', async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};

    const nameError = validateRequiredString(name, 'Name');
    if (nameError) return res.status(400).json(nameError);

    const emailError = validateRequiredString(email, 'Email');
    if (emailError) return res.status(400).json(emailError);

    const passwordError = validateRequiredString(password, 'Password');
    if (passwordError) return res.status(400).json(passwordError);

    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (existingUser) {
      return res.status(409).json({
        error: {
          code: 'EMAIL_EXISTS',
          message: 'An account with this email already exists',
        },
      });
    }

    const cost = Number(process.env.BCRYPT_COST || 12);
    const passwordHash = await bcrypt.hash(password, cost);

    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
      },
    });

    return res.status(201).json({
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    const emailError = validateRequiredString(email, 'Email');
    if (emailError) return res.status(400).json(emailError);

    const passwordError = validateRequiredString(password, 'Password');
    if (passwordError) return res.status(400).json(passwordError);

    const normalizedEmail = email.trim().toLowerCase();
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      return res.status(401).json(INVALID_CREDENTIALS);
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      return res.status(401).json(INVALID_CREDENTIALS);
    }

    return res.status(200).json({
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
