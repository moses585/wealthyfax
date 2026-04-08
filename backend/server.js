const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { promisify } = require('util');
const { createWorker } = require('tesseract.js');

const app = express();
const scryptAsync = promisify(crypto.scrypt);

const PORT = Number(process.env.PORT) || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/wealthyfax';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const VIEW_RATE = 50;
const WITHDRAWAL_MINIMUM = 4000;
const WITHDRAWAL_REFERRALS_REQUIRED = 2;
const SUBMISSION_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const PASSWORD_RESET_EXPIRY_MS = 15 * 60 * 1000;
const DEV_RESET_CODES_VISIBLE = process.env.NODE_ENV !== 'production';

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const safeName = String(file.originalname || 'proof').replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}-${safeName}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (String(file.mimetype || '').startsWith('image/')) return cb(null, true);
    cb(new Error('Only image uploads are allowed'));
  }
});

app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json());
app.use('/uploads', express.static(UPLOADS_DIR));

function cleanUsername(value) {
  return String(value || '').trim();
}

function normalizePhoneNumber(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (/^(254|0)?(7|1)\d{8}$/.test(digits)) {
    if (digits.startsWith('254')) return digits;
    if (digits.startsWith('0')) return `254${digits.slice(1)}`;
    return `254${digits}`;
  }
  return null;
}

function normalizeReferralCode(value) {
  return String(value || '').trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
}

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hashResetCode(code) {
  return crypto.createHash('sha256').update(String(code || '')).digest('hex');
}


let ocrWorkerPromise = null;

async function getOcrWorker() {
  if (!ocrWorkerPromise) {
    ocrWorkerPromise = createWorker('eng');
  }
  return ocrWorkerPromise;
}

function extractNumberCandidates(text) {
  const raw = String(text || '');
  const candidates = new Set();

  const patterns = raw.match(/\d[\d,\.\s]{0,18}/g) || [];
  for (const token of patterns) {
    const digits = token.replace(/\D/g, '');
    if (digits && digits.length <= 9) {
      candidates.add(digits);
    }
  }

  const compact = raw.replace(/[^\d]/g, '');
  if (compact && compact.length <= 9) {
    candidates.add(compact);
  }

  return candidates;
}

async function autoVerifyScreenshotProof(imagePath, submittedViews) {
  const worker = await getOcrWorker();
  const result = await worker.recognize(imagePath);
  const text = String(result?.data?.text || '');
  const confidence = Number(result?.data?.confidence || 0);
  const expected = String(submittedViews).replace(/\D/g, '');
  const candidates = extractNumberCandidates(text);
  const hasExactViewsMatch = candidates.has(expected);
  const hasViewKeyword = /view(s)?/i.test(text);

  let approved = false;
  let notes = 'Screenshot could not be matched to the submitted views number.';

  if (hasExactViewsMatch && confidence >= 25) {
    approved = true;
    notes = hasViewKeyword
      ? 'OCR matched the submitted views number and found a views label.'
      : 'OCR matched the submitted views number in the screenshot.';
  } else if (hasExactViewsMatch) {
    notes = 'Matching number found, but screenshot text was too unclear for auto approval.';
  } else if (confidence < 15) {
    notes = 'Screenshot text was too unclear for automatic verification.';
  }

  return {
    approved,
    confidence,
    extractedText: text.trim().slice(0, 500),
    notes,
    hasExactViewsMatch,
    hasViewKeyword,
    matchedNumbers: Array.from(candidates).slice(0, 20)
  };
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, 64);
  return `scrypt$${salt}$${derivedKey.toString('hex')}`;
}

async function verifyPassword(storedPassword, suppliedPassword) {
  if (!storedPassword || !suppliedPassword) return false;

  if (!storedPassword.startsWith('scrypt$')) {
    return storedPassword === suppliedPassword;
  }

  const parts = storedPassword.split('$');
  if (parts.length !== 3) return false;

  const [, salt, originalHash] = parts;
  const derivedKey = await scryptAsync(suppliedPassword, salt, 64);
  const derivedHex = derivedKey.toString('hex');

  const originalBuffer = Buffer.from(originalHash, 'hex');
  const derivedBuffer = Buffer.from(derivedHex, 'hex');

  if (originalBuffer.length !== derivedBuffer.length) return false;
  return crypto.timingSafeEqual(originalBuffer, derivedBuffer);
}

function baseReferralCodeFromUsername(username) {
  const clean = String(username || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  return clean || `USER${Date.now()}`;
}

async function generateUniqueReferralCode(username) {
  const baseCode = baseReferralCodeFromUsername(username);
  let candidate = baseCode;
  let attempt = 0;

  while (await User.exists({ referralCode: candidate })) {
    attempt += 1;
    const suffix = Math.random().toString(36).slice(2, 6).toUpperCase();
    candidate = `${baseCode}${suffix}`;
    if (attempt > 20) {
      candidate = `${baseCode}${Date.now().toString().slice(-6)}`;
    }
  }

  return candidate;
}

async function ensureReferralCode(user) {
  if (user.referralCode) return user.referralCode;
  user.referralCode = await generateUniqueReferralCode(user.username);
  await user.save();
  return user.referralCode;
}

async function findReferrerByCode(referralCode) {
  const code = normalizeReferralCode(referralCode);
  if (!code) return null;

  const direct = await User.findOne({ referralCode: code });
  if (direct) return direct;

  return User.findOne({
    username: { $regex: new RegExp(`^${escapeRegex(code)}$`, 'i') }
  });
}

function sanitizeUserResponse(user) {
  return {
    username: user.username,
    balance: user.balance,
    views: user.views,
    gold: user.gold,
    activation: user.activation,
    referralCode: user.referralCode,
    referralCount: user.referralCount,
    referredBy: user.referredBy,
    lastSubmission: user.lastSubmission,
    createdAt: user.createdAt
  };
}

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      unique: true,
      required: true,
      trim: true,
      minlength: 3,
      maxlength: 30
    },
    password: {
      type: String,
      required: true
    },
    balance: {
      type: Number,
      default: 0,
      min: 0
    },
    views: {
      type: Number,
      default: 0,
      min: 0
    },
    gold: {
      type: String,
      enum: ['yes', 'no'],
      default: 'no'
    },
    activation: {
      type: String,
      enum: ['yes', 'no'],
      default: 'no'
    },
    goldCreditApplied: {
      type: Boolean,
      default: false
    },
    referralCode: {
      type: String,
      unique: true,
      sparse: true,
      uppercase: true,
      trim: true
    },
    referredBy: {
      type: String,
      default: ''
    },
    referralCount: {
      type: Number,
      default: 0,
      min: 0
    },
    lastSubmission: {
      type: Number,
      default: 0
    },
    passwordResetCodeHash: {
      type: String,
      default: ''
    },
    passwordResetExpiresAt: {
      type: Date,
      default: null
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    versionKey: false
  }
);

const TransactionSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      index: true
    },
    type: {
      type: String,
      required: true,
      trim: true
    },
    amount: {
      type: Number,
      default: 0
    },
    status: {
      type: String,
      enum: ['success', 'pending', 'failed'],
      default: 'success'
    },
    description: {
      type: String,
      default: ''
    },
    meta: {
      type: Object,
      default: {}
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true
    }
  },
  {
    versionKey: false
  }
);


const ViewSubmissionSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      index: true
    },
    views: {
      type: Number,
      required: true,
      min: 1
    },
    screenshotPath: {
      type: String,
      required: true
    },
    screenshotOriginalName: {
      type: String,
      default: ''
    },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending',
      index: true
    },
    verificationMethod: {
      type: String,
      default: 'auto_ocr'
    },
    reviewNotes: {
      type: String,
      default: ''
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true
    },
    reviewedAt: {
      type: Date,
      default: null
    }
  },
  {
    versionKey: false
  }
);

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const ViewSubmission = mongoose.model('ViewSubmission', ViewSubmissionSchema);

async function createTransaction({ username, type, amount = 0, status = 'success', description = '', meta = {} }) {
  try {
    await Transaction.create({ username, type, amount, status, description, meta });
  } catch (error) {
    console.error('Transaction log failed:', error.message);
  }
}

app.get('/api/health', (_req, res) => {
  res.json({ success: true, message: 'API is running' });
});

app.post('/api/register', async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const password = String(req.body.password || '');
    const providedReferralCode = normalizeReferralCode(req.body.referralCode);

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
      return res.status(400).json({
        error: 'Username must be 3-30 characters and use only letters, numbers, or underscores'
      });
    }

    if (password.length !== 4) {
      return res.status(400).json({ error: 'Password must be exactly 4 characters' });
    }

    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(400).json({ error: 'Username exists' });
    }

    let referrer = null;
    if (providedReferralCode) {
      referrer = await findReferrerByCode(providedReferralCode);
      if (!referrer) {
        return res.status(400).json({ error: 'Invalid referral code' });
      }
    }

    const hashedPassword = await hashPassword(password);
    const referralCode = await generateUniqueReferralCode(username);
    const user = new User({
      username,
      password: hashedPassword,
      referralCode,
      referredBy: referrer ? referrer.referralCode || normalizeReferralCode(referrer.username) : ''
    });
    await user.save();

    if (referrer) {
      await ensureReferralCode(referrer);
      referrer.referralCount = Number(referrer.referralCount || 0) + 1;
      await referrer.save();
      await createTransaction({
        username: referrer.username,
        type: 'referral_credit',
        amount: 0,
        description: `New referral joined: ${username}`,
        meta: { referredUser: username }
      });
    }

    await createTransaction({
      username,
      type: 'account_created',
      amount: 0,
      description: 'Account created successfully',
      meta: { referredBy: user.referredBy || null }
    });

    return res.status(201).json({ success: true, message: 'Registration successful' });
  } catch (error) {
    if (error?.code === 11000) {
      return res.status(400).json({ error: 'Username or referral code already exists' });
    }
    return res.status(500).json({ error: 'Failed to register user' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const password = String(req.body.password || '');

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (password.length !== 4) {
      return res.status(400).json({ error: 'Password must be exactly 4 characters' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isValid = await verifyPassword(user.password, password);
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    let changed = false;
    if (!user.password.startsWith('scrypt$')) {
      user.password = await hashPassword(password);
      changed = true;
    }
    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode(user.username);
      changed = true;
    }
    if (changed) {
      await user.save();
    }

    return res.json({ success: true, ...sanitizeUserResponse(user) });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/request-password-reset', async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetCode = String(Math.floor(100000 + Math.random() * 900000));
    user.passwordResetCodeHash = hashResetCode(resetCode);
    user.passwordResetExpiresAt = new Date(Date.now() + PASSWORD_RESET_EXPIRY_MS);
    await user.save();

    return res.json({
      success: true,
      message: 'Password reset code generated',
      expiresInMinutes: PASSWORD_RESET_EXPIRY_MS / (60 * 1000),
      devResetCode: DEV_RESET_CODES_VISIBLE ? resetCode : undefined
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to request password reset' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const resetCode = String(req.body.resetCode || '').trim();
    const newPassword = String(req.body.newPassword || '');

    if (!username || !resetCode || !newPassword) {
      return res.status(400).json({ error: 'Username, reset code, and new password are required' });
    }

    if (newPassword.length !== 4) {
      return res.status(400).json({ error: 'New password must be exactly 4 characters' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.passwordResetCodeHash || !user.passwordResetExpiresAt) {
      return res.status(400).json({ error: 'No active reset code. Request a new one.' });
    }

    if (new Date(user.passwordResetExpiresAt).getTime() < Date.now()) {
      user.passwordResetCodeHash = '';
      user.passwordResetExpiresAt = null;
      await user.save();
      return res.status(400).json({ error: 'Reset code has expired. Request a new one.' });
    }

    if (hashResetCode(resetCode) !== user.passwordResetCodeHash) {
      return res.status(400).json({ error: 'Invalid reset code' });
    }

    user.password = await hashPassword(newPassword);
    user.passwordResetCodeHash = '';
    user.passwordResetExpiresAt = null;
    await user.save();

    return res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.post('/api/activate-gold', async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode(user.username);
    }

    const alreadyActive = user.gold === 'yes';
    let creditedAmount = 0;

    if (!user.goldCreditApplied) {
      creditedAmount = 99;
      user.balance += creditedAmount;
      user.goldCreditApplied = true;
      await createTransaction({
        username,
        type: 'gold_activation_credit',
        amount: creditedAmount,
        description: 'Gold package activated and starter wallet credited',
        meta: { packagePrice: 99 }
      });
    }

    user.gold = 'yes';
    await user.save();

    if (alreadyActive) {
      await createTransaction({
        username,
        type: 'gold_activation_recheck',
        amount: 0,
        description: 'Gold activation was requested again for an already active account'
      });
    }

    return res.json({
      success: true,
      alreadyActive,
      creditedAmount,
      gold: user.gold,
      balance: user.balance,
      views: user.views,
      referralCode: user.referralCode,
      referralCount: user.referralCount
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to activate gold package' });
  }
});

app.post('/api/activate-withdrawal', async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode(user.username);
    }

    user.activation = 'yes';
    await user.save();

    await createTransaction({
      username,
      type: 'withdrawal_activation',
      amount: 0,
      description: 'Withdrawal feature activated',
      meta: { fee: 599 }
    });

    return res.json({
      success: true,
      activation: user.activation,
      referralCount: user.referralCount,
      referralsRequired: WITHDRAWAL_REFERRALS_REQUIRED
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to activate withdrawals' });
  }
});


app.post('/api/submit-views', (req, res, next) => {
  upload.single('screenshot')(req, res, (error) => {
    if (error) {
      return res.status(400).json({ error: error.message || 'Screenshot upload failed' });
    }
    next();
  });
}, async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const views = Number(req.body.views);
    const screenshot = req.file;

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    if (!Number.isFinite(views) || !Number.isInteger(views) || views <= 0) {
      return res.status(400).json({ error: 'Invalid views' });
    }

    if (!screenshot) {
      return res.status(400).json({ error: 'Screenshot proof is required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode(user.username);
      await user.save();
    }

    if (user.gold !== 'yes') {
      return res.status(403).json({ error: 'Gold package required' });
    }

    const now = Date.now();
    const nextAllowedAt = Number(user.lastSubmission || 0) + SUBMISSION_COOLDOWN_MS;
    if (user.lastSubmission && now < nextAllowedAt) {
      return res.status(429).json({
        error: 'You can only submit views once every 24 hours after your last approved proof',
        nextSubmissionAt: nextAllowedAt,
        msRemaining: nextAllowedAt - now
      });
    }

    const verification = await autoVerifyScreenshotProof(screenshot.path, views);
    const earnings = verification.approved ? views * VIEW_RATE : 0;
    const status = verification.approved ? 'approved' : 'rejected';
    const verificationMethod = verification.approved ? 'auto_ocr_verified' : 'auto_ocr_rejected';

    const submission = await ViewSubmission.create({
      username,
      views,
      screenshotPath: `/uploads/${path.basename(screenshot.path)}`,
      screenshotOriginalName: screenshot.originalname || '',
      status,
      verificationMethod,
      reviewNotes: verification.notes,
      reviewedAt: new Date()
    });

    if (verification.approved) {
      user.views += views;
      user.balance += earnings;
      user.lastSubmission = Date.now();
      await user.save();

      await createTransaction({
        username,
        type: 'views_credit',
        amount: earnings,
        status: 'success',
        description: `${views} verified views credited automatically`,
        meta: {
          views,
          rate: VIEW_RATE,
          screenshotPath: submission.screenshotPath,
          verificationMethod,
          ocrConfidence: verification.confidence
        }
      });

      return res.json({
        success: true,
        message: `Screenshot verified automatically. KES ${earnings.toLocaleString()} credited.`,
        verificationStatus: submission.status,
        verificationMethod: submission.verificationMethod,
        submissionId: submission._id,
        screenshotUrl: submission.screenshotPath,
        views,
        rate: VIEW_RATE,
        earnings,
        balance: user.balance,
        verificationNotes: verification.notes,
        ocrConfidence: verification.confidence
      });
    }

    return res.status(400).json({
      error: 'Screenshot verification failed. Make sure the screenshot clearly shows the same views number you entered.',
      verificationStatus: submission.status,
      verificationMethod: submission.verificationMethod,
      submissionId: submission._id,
      screenshotUrl: submission.screenshotPath,
      views,
      rate: VIEW_RATE,
      verificationNotes: verification.notes,
      ocrConfidence: verification.confidence
    });
  } catch (error) {
    console.error('Auto verification failed:', error.message);
    return res.status(500).json({ error: 'Automatic screenshot verification failed. Try again with a clearer screenshot.' });
  }
});

app.get('/api/view-submissions/:username', async (req, res) => {
  try {
    const username = cleanUsername(req.params.username);
    const limit = Math.min(Math.max(Number(req.query.limit) || 5, 1), 20);

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const items = await ViewSubmission.find({ username })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({ success: true, submissions: items });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch screenshot submissions' });
  }
});

app.post('/api/withdraw', async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const amount = Number(req.body.amount);
    const phone = normalizePhoneNumber(req.body.phone);

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    if (!phone) {
      return res.status(400).json({ error: 'Invalid M-Pesa number' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode(user.username);
      await user.save();
    }

    if (user.activation !== 'yes') {
      return res.status(400).json({
        error: 'Activation required',
        needsActivation: true
      });
    }

    if (Number(user.referralCount || 0) < WITHDRAWAL_REFERRALS_REQUIRED) {
      return res.status(400).json({
        error: `You need at least ${WITHDRAWAL_REFERRALS_REQUIRED} referrals before withdrawing`,
        needsReferrals: true,
        referralCount: Number(user.referralCount || 0),
        referralsRequired: WITHDRAWAL_REFERRALS_REQUIRED
      });
    }

    if (amount < WITHDRAWAL_MINIMUM) {
      return res.status(400).json({ error: `Minimum ${WITHDRAWAL_MINIMUM}` });
    }

    if (amount > user.balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    user.balance -= amount;
    await user.save();

    await createTransaction({
      username,
      type: 'withdrawal_request',
      amount: -Math.abs(amount),
      status: 'pending',
      description: `Withdrawal requested to M-Pesa ${phone}`,
      meta: { phone, minimum: WITHDRAWAL_MINIMUM }
    });

    return res.json({
      success: true,
      balance: user.balance,
      phone,
      message: 'Withdrawal request accepted'
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

app.get('/api/user/:username', async (req, res) => {
  try {
    const username = cleanUsername(req.params.username);
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.referralCode) {
      user.referralCode = await generateUniqueReferralCode(user.username);
      await user.save();
    }

    return res.json(sanitizeUserResponse(user));
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

app.get('/api/transactions/:username', async (req, res) => {
  try {
    const username = cleanUsername(req.params.username);
    const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const transactions = await Transaction.find({ username, amount: { $ne: 0 } })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({ success: true, transactions });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.use((req, res) => {
  return res.status(404).json({ error: 'Route not found' });
});

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('MongoDB error:', err.message);
    process.exit(1);
  });
