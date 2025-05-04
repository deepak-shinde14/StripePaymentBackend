require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const session = require('express-session');
const Transaction = require('./models/Transaction');
const swaggerSetup = require('./swagger');

const app = express();

// Swagger documentation setup
swaggerSetup(app);

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(session({
  name: 'connect.sid', // explicit session cookie name
  secret: process.env.COOKIE_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: false, // set to true in production with HTTPS
    httpOnly: true,
    sameSite: 'lax' // helps with CSRF protection
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Add this at the end of server.js (before app.listen)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Database connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User model
const User = require('./models/User');

// Passport Google OAuth setup
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = new User({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          avatar: profile.photos[0].value,
          role: 'user', // Default role
          isActive: true // Default active status
        });
        await user.save();
      }

      // Check if user is active
      if (!user.isActive) {
        return done(null, false, { message: 'Account is deactivated' });
      }

      return done(null, user);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Routes

/**
 * @swagger
 * /auth/google:
 *   get:
 *     summary: Initiate Google OAuth authentication
 *     description: Redirects to Google's OAuth consent screen
 *     tags: [Authentication]
 *     responses:
 *       302:
 *         description: Redirect to Google OAuth
 */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

/**
 * @swagger
 * /auth/google/callback:
 *   get:
 *     summary: Google OAuth callback
 *     description: Handles the Google OAuth callback after authentication
 *     tags: [Authentication]
 *     responses:
 *       302:
 *         description: Redirect to client with authentication result
 */
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect to client with user data
    res.redirect(`${process.env.CLIENT_URL}/?success=true`);
  }
);

/**
 * @swagger
 * /api/v1/logout:
 *   get:
 *     summary: Logout current user
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: Successfully logged out
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *       500:
 *         description: Logout failed
 */
app.get('/api/v1/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send('Logout failed');
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
        return res.status(500).send('Logout failed');
      }
      res.clearCookie('connect.sid'); // This should match your session cookie name
      res.send({ success: true });
    });
  });
});

/**
 * @swagger
 * /api/v1/current_user:
 *   get:
 *     summary: Get current authenticated user
 *     tags: [Users]
 *     responses:
 *       200:
 *         description: Returns the current user object
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 */
app.get('/api/v1/current_user', (req, res) => {
  res.send(req.user);
});

// Stripe payment intent
/**
 * @swagger
 * /api/v1/create-payment-intent:
 *   post:
 *     summary: Create a Stripe payment intent
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount:
 *                 type: number
 *                 description: Amount in cents
 *                 example: 1000
 *               description:
 *                 type: string
 *                 description: Payment description
 *                 example: "Mock payment"
 *     responses:
 *       200:
 *         description: Payment intent created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 clientSecret:
 *                   type: string
 *                   description: Stripe client secret for confirming payment
 *                 paymentIntentId:
 *                   type: string
 *                   description: Stripe payment intent ID
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Stripe error
 */
app.post('/api/v1/create-payment-intent', async (req, res) => {
  if (!req.user) return res.status(401).send('Unauthorized');

  try {
    const { amount, description } = req.body;

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount,
      currency: 'usd',
      description: description || 'Mock payment',
      metadata: {
        userId: req.user._id.toString(),
        userEmail: req.user.email,
        mockTransaction: 'true'
      }
    });

    // Create and save the transaction
    const transaction = new Transaction({
      paymentIntentId: paymentIntent.id,
      userId: req.user._id,
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      status: 'pending',
      description: paymentIntent.description,
      metadata: paymentIntent.metadata
    });
    await transaction.save();

    res.send({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id
    });
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).send({ error: err.message });
  }
});

//endpoint for token-based Google auth

/**
 * @swagger
 * /auth/google:
 *   get:
 *     summary: Initiate Google OAuth authentication
 *     description: Redirects to Google's OAuth consent screen
 *     tags: [Authentication]
 *     responses:
 *       302:
 *         description: Redirect to Google OAuth
 */
app.post('/auth/google', async (req, res) => {
  try {
    const { token } = req.body;

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    let user = await User.findOne({ googleId: payload.sub });
    if (!user) {
      user = new User({
        googleId: payload.sub,
        email: payload.email,
        name: payload.name,
        avatar: payload.picture,
        role: 'user', // Default role
        isActive: true // Default active status
      });
      await user.save();
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Log in the user
    req.login(user, (err) => {
      if (err) {
        throw err;
      }
      res.status(200).json(user);
    });

  } catch (err) {
    console.error('Google auth error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Mock transaction history
/**
 * @swagger
 * /api/v1/transactions:
 *   get:
 *     summary: Get user's transaction history
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of user's transactions
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Transaction'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Failed to fetch transactions
 */
app.get('/api/v1/transactions', async (req, res) => {
  if (!req.user) return res.status(401).send('Unauthorized');

  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .lean();

    res.send(transactions);
  } catch (err) {
    console.error('Error fetching transactions:', err);
    res.status(500).send({ error: 'Failed to fetch transactions' });
  }
});

// Add these routes to ./server/server.js

// Middleware to check if user is superadmin
const isSuperAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'superadmin') {
    return next();
  }
  return res.status(403).send('Forbidden: Super Admin access required');
};

// Get all users (Super Admin only)
/**
 * @swagger
 * /api/v1/users:
 *   get:
 *     summary: Get all users (Super Admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 *       403:
 *         description: Forbidden - Super Admin access required
 *       500:
 *         description: Failed to fetch users
 */
app.get('/api/v1/users', isSuperAdmin, async (req, res) => {
  try {
    const users = await User.find({}, { googleId: 0, __v: 0 });
    res.send(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send({ error: 'Failed to fetch users' });
  }
});

// Update user status (Super Admin only)
/**
 * @swagger
 * /api/v1/users/{id}/status:
 *   put:
 *     summary: Update user active status (Super Admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               isActive:
 *                 type: boolean
 *                 description: New active status
 *     responses:
 *       200:
 *         description: User status updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       403:
 *         description: Forbidden - Super Admin access required
 *       404:
 *         description: User not found
 *       500:
 *         description: Failed to update user status
 */
app.put('/api/v1/users/:id/status', isSuperAdmin, async (req, res) => {
  try {
    const { isActive } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive },
      { new: true }
    );

    if (!user) {
      return res.status(404).send('User not found');
    }

    res.send(user);
  } catch (err) {
    console.error('Error updating user status:', err);
    res.status(500).send({ error: 'Failed to update user status' });
  }
});

// Update user role (Super Admin only)
/**
 * @swagger
 * /api/v1/users/{id}/role:
 *   put:
 *     summary: Update user role (Super Admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [user, admin, superadmin]
 *                 description: New user role
 *     responses:
 *       200:
 *         description: User role updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       403:
 *         description: Forbidden - Super Admin access required
 *       404:
 *         description: User not found
 *       500:
 *         description: Failed to update user role
 */
app.put('/api/v1/users/:id/role', isSuperAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    );

    if (!user) {
      return res.status(404).send('User not found');
    }

    res.send(user);
  } catch (err) {
    console.error('Error updating user role:', err);
    res.status(500).send({ error: 'Failed to update user role' });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));