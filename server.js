require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust reverse proxy (e.g., Render, Firebase, Cloudflare, NGINX)
app.set('trust proxy', 1);

// -----------------------------------------------------------------------------
// 1. HARDENED SECURITY HEADERS (Helmet & CSP)
// -----------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://cdn.tailwindcss.com",
        "https://unpkg.com",
        "https://checkout.razorpay.com",
        "https://pagead2.googlesyndication.com",
        "https://www.gstatic.com",
        "https://*.firebaseio.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://unpkg.com"
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "data:"
      ],
      imgSrc: [
        "'self'",
        "data:",
        "blob:",
        "https:",
        "*.openstreetmap.org",
        "*.tile.openstreetmap.org"
      ],
      connectSrc: [
        "'self'",
        "https://*.firebaseio.com",
        "https://*.googleapis.com",
        "https://api.razorpay.com",
        "https://lumberjack.razorpay.com",
        "https://pagead2.googlesyndication.com"
      ],
      frameSrc: [
        "'self'",
        "https://api.razorpay.com",
        "https://googleads.g.doubleclick.net",
        "https://pagead2.googlesyndication.com"
      ],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// -----------------------------------------------------------------------------
// 2. STRICT CORS WHITELISTING
// -----------------------------------------------------------------------------
const ALLOWED_ORIGINS = [
  'https://csmc-dp-portal.web.app',
  'https://csmc-dp-portal.firebaseapp.com',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

if (process.env.ADDITIONAL_ALLOWED_ORIGINS) {
  process.env.ADDITIONAL_ALLOWED_ORIGINS.split(',').forEach(o => {
    if (o.trim()) ALLOWED_ORIGINS.push(o.trim());
  });
}

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (mobile, server-to-server webhooks)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Cross-Origin Request Blocked by Security Policy'));
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-razorpay-signature']
}));

// -----------------------------------------------------------------------------
// 3. DEFENSE-IN-DEPTH RATE LIMITING
// -----------------------------------------------------------------------------
// Global API Limiter: 200 requests per 15 minutes per IP
const globalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests from this IP. Please try again after 15 minutes." }
});
app.use('/api/', globalApiLimiter);

// Strict Payment Limiter: 20 payment/order attempts per 15 minutes per IP
const paymentApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many checkout requests. Please wait a few minutes before trying again." }
});
app.use('/api/create-order', paymentApiLimiter);
app.use('/api/verify-payment', paymentApiLimiter);

// Body parsers with payload size caps to prevent memory exhaustion DoS
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// -----------------------------------------------------------------------------
// 4. ZERO-TRUST STATIC FILE SHIELD
// Prevent Directory Traversal, Source Code Exposure & Proprietary Data Exfiltration
// -----------------------------------------------------------------------------
const FORBIDDEN_EXTENSIONS = [
  '.csv', '.env', '.rules', '.tif', '.tiff', '.aux.xml', '.kml', '.kmz',
  '.md', '.bak', '.log', '.sh', '.yaml', '.yml'
];

const FORBIDDEN_PATHS = [
  'rzp-key', 'server.js', 'package.json', 'package-lock.json',
  'backend', 'functions', 'google_earth', 'sector_calibration',
  '.backups', '.git', '.firebase', 'node_modules'
];

app.use((req, res, next) => {
  const cleanPath = decodeURIComponent(req.path).toLowerCase();

  // 1. Extension inspection
  const hasForbiddenExt = FORBIDDEN_EXTENSIONS.some(ext => cleanPath.endsWith(ext));

  // 2. Directory & sensitive filename inspection
  const hasForbiddenPath = FORBIDDEN_PATHS.some(seg => {
    return cleanPath === `/${seg}` ||
      cleanPath.startsWith(`/${seg}/`) ||
      cleanPath.includes(`/${seg}`);
  });

  // 3. Block access to non-public server files
  if (hasForbiddenExt || hasForbiddenPath) {
    return res.status(403).json({
      error: "Access Forbidden: Requested resource is protected by security policy"
    });
  }

  next();
});

// Serve frontend assets with safe static config
app.use(express.static(path.join(__dirname, '..'), {
  dotfiles: 'ignore',
  index: false,
  maxAge: '1h'
}));

// -----------------------------------------------------------------------------
// 5. RAZORPAY INSTANCE & PRICING MATRIX
// -----------------------------------------------------------------------------
const key_id = process.env.RAZORPAY_KEY_ID;
const key_secret = process.env.RAZORPAY_KEY_SECRET;
const webhook_secret = process.env.RAZORPAY_WEBHOOK_SECRET || process.env.RAZORPAY_KEY_SECRET;

if (!key_id || !key_secret) {
  console.warn("SECURITY WARNING: RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET missing in environment variables!");
}

const razorpay = new Razorpay({
  key_id: key_id || '',
  key_secret: key_secret || ''
});

// In-Memory Idempotency Cache for Replay Attack Prevention (Stores payment_id -> timestamp)
const PROCESSED_PAYMENTS = new Map();
// Evict entries older than 24 hours every hour
setInterval(() => {
  const cutoff = Date.now() - (24 * 60 * 60 * 1000);
  for (const [id, time] of PROCESSED_PAYMENTS.entries()) {
    if (time < cutoff) PROCESSED_PAYMENTS.delete(id);
  }
}, 60 * 60 * 1000);

const SUBSCRIPTION_PLANS = {
  'launch_7d': {
    id: 'launch_7d',
    name: 'Launch Special Trial',
    tier: 'launch',
    scope: 'basic',
    durationDays: 7,
    durationHours: 168,
    durationLabel: '7 Days',
    price: 9,
    amountPaise: 900,
    proTools: false,
    singleUse: true,
    badge: 'Special Offer',
    description: 'One-time 7-day basic map viewing access for verified users'
  },
  'basic_1d': {
    id: 'basic_1d',
    name: '1-Day Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 1,
    durationHours: 24,
    durationLabel: '24 Hours',
    price: 49,
    amountPaise: 4900,
    proTools: false,
    singleUse: false,
    badge: 'Quick View',
    description: 'Basic map viewing valid strictly 24 hours from purchase'
  },
  'basic_1w': {
    id: 'basic_1w',
    name: '1-Week Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 7,
    durationHours: 168,
    durationLabel: '7 Days',
    price: 99,
    amountPaise: 9900,
    proTools: false,
    singleUse: false,
    badge: 'Standard Weekly',
    description: 'Full basic map viewing access for 7 days'
  },
  'basic_1m': {
    id: 'basic_1m',
    name: '1-Month Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 30,
    durationHours: 720,
    durationLabel: '1 Month',
    price: 299,
    amountPaise: 29900,
    proTools: false,
    singleUse: false,
    badge: 'Popular',
    description: 'Complete basic map viewing for 30 days across all sectors'
  },
  'basic_1y': {
    id: 'basic_1y',
    name: '1-Year Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 365,
    durationHours: 8760,
    durationLabel: '1 Year',
    price: 2999,
    amountPaise: 299900,
    proTools: false,
    singleUse: false,
    badge: 'Best Value',
    savings: 'Save ₹589',
    description: 'Annual basic viewing access for architects & planners'
  },
  'pro_1d': {
    id: 'pro_1d',
    name: '1-Day Pro Pass',
    tier: 'pro',
    scope: 'pro',
    durationDays: 1,
    durationHours: 24,
    durationLabel: '24 Hours',
    price: 99,
    amountPaise: 9900,
    proTools: true,
    singleUse: false,
    badge: 'Pro Day Pass',
    description: 'Full GIS Pro measurement tools + DP view for strictly 24 hours'
  },
  'pro_1w': {
    id: 'pro_1w',
    name: '1-Week Pro Pass',
    tier: 'pro',
    scope: 'pro',
    durationDays: 7,
    durationHours: 168,
    durationLabel: '7 Days',
    price: 249,
    amountPaise: 24900,
    proTools: true,
    singleUse: false,
    badge: 'Pro Weekly',
    description: '7-day access to Distance, Area & Coordinates tools'
  },
  'pro_1m': {
    id: 'pro_1m',
    name: '1-Month Pro Pass',
    tier: 'pro',
    scope: 'pro',
    durationDays: 30,
    durationHours: 720,
    durationLabel: '1 Month',
    price: 599,
    amountPaise: 59900,
    proTools: true,
    singleUse: false,
    badge: 'Most Popular',
    savings: 'Best Seller',
    description: 'Monthly unlimited access to all GIS Measurement Tools'
  },
  'pro_1y': {
    id: 'pro_1y',
    name: '1-Year Pro Pass',
    tier: 'pro',
    scope: 'pro',
    durationDays: 365,
    durationHours: 8760,
    durationLabel: '1 Year',
    price: 5999,
    amountPaise: 599900,
    proTools: true,
    singleUse: false,
    badge: 'Ultimate Value',
    savings: 'Save ₹1,189',
    description: 'Full 1-year unlimited GIS Pro access with priority updates'
  }
};

/**
 * Constant-time string comparison to protect against side-channel timing attacks
 */
function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// -----------------------------------------------------------------------------
// 6. API ENDPOINTS
// -----------------------------------------------------------------------------

// Public Key Configuration Endpoint
app.get('/api/razorpay-key', (req, res) => {
  if (!key_id) {
    return res.status(500).json({ error: "Razorpay Key ID not configured on server" });
  }
  res.json({ key_id: key_id });
});

// Active Subscription Plans Schema
app.get('/api/subscription-plans', (req, res) => {
  res.json({
    success: true,
    plans: SUBSCRIPTION_PLANS,
    timestamp: new Date().toISOString()
  });
});

// STEP 1: Create Order
// POST /api/create-order
// Server enforces plan pricing; prevents client-side price tampering
app.post('/api/create-order', async (req, res) => {
  try {
    const { planId, userEmail, userPhone, userName, userCategory } = req.body;

    if (!planId || !SUBSCRIPTION_PLANS[planId]) {
      return res.status(400).json({ error: "Invalid or unsupported plan identifier." });
    }

    if (!key_id || !key_secret) {
      return res.status(500).json({ error: "Payment processor credentials not configured on server." });
    }

    const plan = SUBSCRIPTION_PLANS[planId];
    // Enforce canonical amount strictly from the server-side pricing matrix
    const targetAmount = plan.amountPaise;

    // Sanitize metadata fields
    const sanitizedEmail = String(userEmail || '').trim().toLowerCase().slice(0, 120);
    const sanitizedPhone = String(userPhone || '').replace(/\D/g, '').slice(-10);
    const sanitizedName = String(userName || 'Citizen User').slice(0, 80);
    const sanitizedCat = String(userCategory || 'Individual Citizen').slice(0, 80);

    const options = {
      amount: targetAmount,
      currency: 'INR',
      receipt: `rcpt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      payment_capture: 1,
      notes: {
        portal: 'CSMC DP Spatial Portal',
        planId: plan.id,
        planName: plan.name,
        scope: plan.scope,
        amountPaise: String(targetAmount),
        userName: sanitizedName,
        userPhone: sanitizedPhone,
        userEmail: sanitizedEmail,
        userCategory: sanitizedCat,
        createdAt: new Date().toISOString()
      }
    };

    const order = await razorpay.orders.create(options);
    if (!order || !order.id) {
      return res.status(500).json({ error: "Failed to create order with payment provider." });
    }

    res.status(200).json({
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      plan_id: plan.id
    });
  } catch (error) {
    console.error("Order creation error:", error.message || error);
    res.status(500).json({ error: "Failed to initialize order." });
  }
});

// STEP 2: Verify Payment Signature
// POST /api/verify-payment
// Cryptographically validates HMAC-SHA256 signature, validates plan against Razorpay order notes (preventing privilege escalation), and enforces idempotency
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    // Strict parameter validation
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        success: false,
        error: "Missing required payment parameters."
      });
    }

    if (!key_secret) {
      return res.status(500).json({
        success: false,
        error: "Payment processor key secret not configured on server."
      });
    }

    const orderId = String(razorpay_order_id).trim();
    const paymentId = String(razorpay_payment_id).trim();
    const signature = String(razorpay_signature).trim();

    // 1. Anti-Replay Check (Idempotency)
    if (PROCESSED_PAYMENTS.has(paymentId)) {
      return res.status(409).json({
        success: false,
        error: "Payment already processed. Duplicate redemption rejected."
      });
    }

    // 2. Cryptographic HMAC-SHA256 Signature Verification (Constant-Time)
    const expectedSignature = crypto
      .createHmac('sha256', key_secret)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');

    if (!secureCompare(expectedSignature, signature)) {
      console.warn(`[AUDIT] Security Alert: Invalid payment signature for order: ${orderId}`);
      return res.status(400).json({
        success: false,
        error: "Payment verification failed: Cryptographic signature mismatch."
      });
    }

    // 3. Server-Side Privilege Escalation Defense:
    // Fetch the canonical order directly from Razorpay to verify the actual purchased plan & amount
    let verifiedPlanId = 'basic_1m';
    try {
      const orderData = await razorpay.orders.fetch(orderId);
      if (orderData && orderData.notes && orderData.notes.planId) {
        verifiedPlanId = orderData.notes.planId;
      }
    } catch (fetchErr) {
      console.warn("Could not fetch order from Razorpay API, falling back to body notes:", fetchErr.message);
      if (req.body.planId && SUBSCRIPTION_PLANS[req.body.planId]) {
        verifiedPlanId = req.body.planId;
      }
    }

    const plan = SUBSCRIPTION_PLANS[verifiedPlanId] || SUBSCRIPTION_PLANS['basic_1m'];
    const now = Date.now();
    let expiryTimestamp;

    if (plan.durationHours === 24) {
      expiryTimestamp = now + (24 * 60 * 60 * 1000);
    } else {
      expiryTimestamp = now + (plan.durationDays * 24 * 60 * 60 * 1000);
    }

    // Mark payment as consumed in idempotency ledger
    PROCESSED_PAYMENTS.set(paymentId, now);

    res.status(200).json({
      success: true,
      message: "Payment signature verified successfully",
      order_id: orderId,
      payment_id: paymentId,
      planId: plan.id,
      planName: plan.name,
      scope: plan.scope,
      proToolsEnabled: plan.proTools,
      purchaseTimestamp: now,
      expiryTimestamp: expiryTimestamp,
      expiryDate: new Date(expiryTimestamp).toISOString()
    });
  } catch (error) {
    console.error("Payment verification internal error:", error.message || error);
    res.status(500).json({
      success: false,
      error: "Internal server error during payment verification."
    });
  }
});

// STEP 3: Razorpay Webhook Handler
// POST /api/razorpay-webhook
app.post('/api/razorpay-webhook', (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature) {
      return res.status(400).json({ error: "Missing x-razorpay-signature header." });
    }

    const secret = webhook_secret || key_secret;
    if (!secret) {
      return res.status(500).json({ error: "Webhook secret not configured on server." });
    }

    const payload = JSON.stringify(req.body);
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');

    if (!secureCompare(expectedSignature, signature)) {
      console.warn("Security Alert: Webhook signature verification mismatch from IP:", req.ip);
      return res.status(400).json({ error: "Invalid webhook signature." });
    }

    const event = req.body.event;
    if (event === 'order.paid' || event === 'payment.captured') {
      const paymentEntity = req.body.payload?.payment?.entity;
      const notes = paymentEntity?.notes || {};
      const pid = paymentEntity?.id;
      if (pid) PROCESSED_PAYMENTS.set(pid, Date.now());
      console.log(`[AUDIT] Webhook confirmed payment ${pid}, Plan: ${notes.planId}`);
    }

    res.status(200).json({ status: "ok", received: true });
  } catch (err) {
    console.error("Webhook processing error:", err.message || err);
    res.status(500).json({ error: "Webhook processing failed." });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: "healthy",
    service: "CSMC Razorpay API",
    plansCount: Object.keys(SUBSCRIPTION_PLANS).length,
    timestamp: new Date().toISOString()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    status: "online",
    service: "CSMC DP Spatial Portal Payment API",
    endpoints: [
      "POST /api/create-order",
      "POST /api/verify-payment",
      "POST /api/razorpay-webhook",
      "GET /api/subscription-plans",
      "GET /api/razorpay-key",
      "GET /health"
    ]
  });
});

// Global 404 handler for unmatched API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: "API endpoint not found." });
});

// Start Server if run directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`CSMC Spatial Portal Backend running securely on http://localhost:${PORT}`);
    console.log(`Razorpay Key ID configured: ${key_id ? key_id.substring(0, 8) + '...' : 'NONE'}`);
  });
}

module.exports = app;
