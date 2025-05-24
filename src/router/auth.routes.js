import { Router } from 'express';
import User from '../models/User.js';
import Referral from '../models/Referral.js';
import bcrypt from 'bcrypt';
import { check, validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import crypto from 'crypto';
import authMiddleware from '../middleware/auth.js';
import uploadAvatar from '../middleware/uploadAvatar.js';

dotenv.config();

function generateEncryptionKey() {
  const key = crypto.randomBytes(32).toString('hex');
  const iv = crypto.randomBytes(16).toString('hex');
  return { privateKeyPart: key, iv };
}

function encryptPrivateKeyPart(privateKeyPart, secretKey, iv) {
  const keyBuffer = Buffer.from(secretKey, 'hex');
  const ivBuffer = Buffer.from(iv, 'hex');

  if (keyBuffer.length !== 32 || ivBuffer.length !== 16) {
    throw new Error('Invalid key or IV length');
  }

  const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, ivBuffer);
  let encrypted = cipher.update(privateKeyPart, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptPrivateKeyPart(encryptedPrivateKeyPart, secretKey, iv) {
  const keyBuffer = Buffer.from(secretKey, 'hex');
  const ivBuffer = Buffer.from(iv, 'hex');

  if (keyBuffer.length !== 32 || ivBuffer.length !== 16) {
    throw new Error('Invalid key or IV length');
  }

  const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
  let decrypted = decipher.update(encryptedPrivateKeyPart, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function validateSecurityQuestions(inputQuestions, storedQuestions) {
  if (!inputQuestions || !storedQuestions) return false;

  const inputEntries = Object.entries(inputQuestions)
    .map(([q, a]) => ({ question: q, answer: a }))
    .sort((a, b) => a.question.localeCompare(b.question));

  const storedEntries = Object.entries(storedQuestions)
    .map(([q, a]) => ({ question: q, answer: a }))
    .sort((a, b) => a.question.localeCompare(b.question));

  return JSON.stringify(inputEntries) === JSON.stringify(storedEntries);
}

function generateTokens(userId) {
  const accessToken = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '1d' });
  return { accessToken, refreshToken };
}

const authRouter = Router();

authRouter.post('/invite', authMiddleware, async (req, res) => {
  try {
    const inviterId = req.user.id;
    const code = crypto.randomBytes(16).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await new Referral({ code, inviter: inviterId, expiresAt }).save();

    res.json({ message: 'Referral created', code });
  } catch (err) {
    res.status(500).json({ message: 'Could not create referral' });
  }
});


authRouter.post(
  '/register',
  [
    check(
      'password',
      'Password must be at least 8 characters long, contain at least one uppercase letter, one digit, and one special character'
    )
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
    check('userName', 'User name must be at least 3 characters long').isLength({ min: 3 }),
    check('securityQuestions', 'Security questions must be provided').notEmpty(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array(), message: 'Invalid data' });
      }

      const code = req.header('x-referral-key');
      if (!code) {
        return res.status(400).json({ message: 'Referral key is required' });
      }

      const referral = await Referral.findOne({ code });
      if (!referral) {
        return res.status(400).json({ message: 'Invalid referral key' });
      }

      if (referral.used) {
        return res.status(400).json({ message: 'Referral key already used' });
      }

      if (referral.expiresAt < new Date()) {
        return res.status(400).json({ message: 'Referral key has expired' });
      }

      const { password, userName, securityQuestions } = req.body;
      const candidate = await User.findOne({ userName });
      if (candidate) {
        return res.status(400).json({ message: 'This user Name has already been registered' });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const { privateKeyPart, iv } = generateEncryptionKey();

      const secretKey = process.env.SECRET_KEY;
      if (!secretKey || secretKey.length !== 64) {
        throw new Error(secretKey.length);
      }

      const encryptedPrivateKeyPart = encryptPrivateKeyPart(privateKeyPart, secretKey, iv);

      const user = new User({
        password: hashedPassword,
        userName,
        securityQuestions,
        iv,
        encryptedPrivateKeyPart,
        referredBy: referral.inviter,
      });

      await user.save();

      referral.used = true;
      await referral.save();

      res.status(201).json({ message: 'User created', privateKeyPart });
    } catch (err) {
      res.status(500).json({ message: 'Registration error', error: err.message });
    }
  }
);

authRouter.post('/validate-reset', async (req, res) => {
  try {
    const { userName, securityQuestions, privateKeyPart } = req.body;
    const user = await User.findOne({ userName });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    if (!validateSecurityQuestions(securityQuestions, user.securityQuestions)) {
      return res.status(400).json({ message: 'Security questions do not match' });
    }

    if (!user.encryptedPrivateKeyPart) {
      return res.status(500).json({ message: 'Missing encryptedPrivateKeyPart in database' });
    }

    const secretKey = process.env.SECRET_KEY;
    const decryptedPrivateKeyPart = decryptPrivateKeyPart(
      user.encryptedPrivateKeyPart,
      secretKey,
      user.iv
    );

    if (privateKeyPart !== decryptedPrivateKeyPart) {
      return res.status(403).json({ message: 'Invalid key combination' });
    }

    const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET_RESET, {
      expiresIn: '5m',
    });

    res.status(200).json({ message: 'Validation successful', resetToken });
  } catch (err) {
    res.status(500).json({ message: 'Validation error', error: err.message });
  }
});

authRouter.post('/reset-password', async (req, res) => {
  try {
    const { newPassword, resetToken } = req.body;
    if (!resetToken) {
      return res.status(403).json({ message: 'Missing reset token' });
    }

    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET_RESET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Reset password error' });
  }
});

authRouter.post(
  '/login',
  [
    check('userName', 'User name must be at least 3 characters long').isLength({ min: 3 }),
    check('password', 'Invalid password').isLength({ min: 8 }),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array(), message: 'Invalid data' });
      }

      const { userName, password } = req.body;
      const user = await User.findOne({ userName });
      if (!user || !password) {
        return res.status(400).json({ message: 'Invalid data' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid data' });
      }

      const { accessToken, refreshToken } = generateTokens(user.id);
      res.json({ accessToken, refreshToken});
    } catch (err) {
      res.status(500).json({ message: 'Login error', error: err.message });
    }
  }
);

authRouter.post('/refresh', async (req, res) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      return res.status(403).json({ message: 'Missing refresh token header' });
    }

    const parts = authHeader.split(' ');
    if (parts[0] !== 'Bearer' || !parts[1]) {
      return res.status(403).json({ message: 'Invalid refresh token format' });
    }

    const refreshToken = parts[1];

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    const newAccessToken = jwt.sign(
      { userId: payload.userId },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(500).json({ message: 'Token refresh error', error: err.message });
  }
});


authRouter.put(
  '/update-profile',
  authMiddleware,
  uploadAvatar,      
  async (req, res) => {
    try {
      const { avatarUrl } = req.body;
      const userId = req.user.id;

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      if (avatarUrl) {
        user.avatarUrl = avatarUrl;
      }

      await user.save();
      res
        .status(200)
        .json({ message: 'Profile updated', avatarUrl: user.avatarUrl });
    } catch (err) {
      res
        .status(500)
        .json({ message: 'Profile update error', error: err.message });
    }
  }
);


authRouter.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    res.json({
      userId: user._id,
      userName: user.userName,
      avatarUrl: user.avatarUrl,
    })
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch user data', error: err.message })
  }
})

authRouter.get('/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      userId:    user._id,
      userName:  user.userName,
      avatarUrl: user.avatarUrl,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: 'Could not fetch user data', error: err.message });
  }
});

export default authRouter;
