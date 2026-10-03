require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Firebase Admin SDK for authoritative Firestore writes
let adminDb = null;
try {
  const admin = require('firebase-admin');
  if (!admin.apps.length) {
    let serviceAccount = null;

    // 1. Try env variable FIREBASE_SERVICE_ACCOUNT (raw JSON or base64)
    const rawEnv = process.env.FIREBASE_SERVICE_ACCOUNT || process.env.FIREBASE_CONFIG_JSON;
    if (rawEnv && rawEnv.trim()) {
      const trimmed = rawEnv.trim();
      try {
        if (trimmed.startsWith('{')) {
          serviceAccount = JSON.parse(trimmed);
        } else {
          // Attempt Base64 decode
          const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
          serviceAccount = JSON.parse(decoded);
        }
      } catch (err) {
        console.error('[Firebase] Error parsing FIREBASE_SERVICE_ACCOUNT env var:', err.message);
      }
    }

    // 2. Try secret file locations (Render Secret Files, custom paths, or local file)
    if (!serviceAccount) {
      const candidatePaths = [
        process.env.FIREBASE_SERVICE_ACCOUNT_PATH,
        process.env.GOOGLE_APPLICATION_CREDENTIALS,
        '/etc/secrets/serviceAccount.json',
        '/etc/secrets/FIREBASE_SERVICE_ACCOUNT',
        path.join(__dirname, 'serviceAccount.json')
      ].filter(Boolean);

      for (const p of candidatePaths) {
        if (fs.existsSync(p)) {
          try {
            const content = fs.readFileSync(p, 'utf8');
            serviceAccount = JSON.parse(content);
            console.log(`[Firebase] Loaded service account credentials from: ${p}`);
            break;
          } catch (e) {
            console.warn(`[Firebase] Failed reading service account from ${p}:`, e.message);
          }
        }
      }
    }

    if (serviceAccount && serviceAccount.private_key) {
      // Fix private key newlines if they were escaped as string literal \n
      if (typeof serviceAccount.private_key === 'string') {
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
      }
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: serviceAccount.project_id || 'csmc-dp-portal'
      });
      console.log('[Firebase] Admin SDK initialized successfully with service account');
      adminDb = admin.firestore();
    } else {
      console.warn('[Firebase] No valid service account provided. Firestore writes will be skipped.');
    }
  } else {
    adminDb = admin.firestore();
  }
  if (adminDb) {
    console.log('[Firebase] Firestore connection ready');
  }
} catch (fbErr) {
  console.warn('[Firebase] Admin SDK unavailable — Firestore writes will be skipped:', fbErr.message);
}


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
app.use('/api/create-razorpay-order', paymentApiLimiter);
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
// In-Memory Cache of Verified Subscriptions for Instant Restoration & Redundancy
const VERIFIED_SUBSCRIPTIONS = new Map();
// Single-Use Trial Phone Ledger (Ensures ₹9 trial pass cannot be claimed multiple times)
const CLAIMED_TRIAL_PHONES = new Set();

/**
 * Standard Indian Mobile Normalizer: strips +91, 0, spaces, and dashes
 */
function normalizeIndianPhone(input) {
  if (!input) return '';
  const digits = String(input).replace(/\D/g, '');
  if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
  if (digits.length === 11 && digits.startsWith('0')) return digits.slice(1);
  return digits.length >= 10 ? digits.slice(-10) : digits;
}

// Evict entries older than 30 days every 2 hours
setInterval(() => {
  const cutoff = Date.now() - (24 * 60 * 60 * 1000);
  for (const [id, time] of PROCESSED_PAYMENTS.entries()) {
    if (time < cutoff) PROCESSED_PAYMENTS.delete(id);
  }
  const subCutoff = Date.now() - (30 * 24 * 60 * 60 * 1000);
  for (const [id, sub] of VERIFIED_SUBSCRIPTIONS.entries()) {
    if ((sub.expiryTimestamp || 0) < subCutoff) VERIFIED_SUBSCRIPTIONS.delete(id);
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
    badge: '3-Day Special Offer',
    description: 'Special 3-day introductory launch trial. Regular tariffs apply thereafter.'
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
  'basic_7d': {
    id: 'basic_7d',
    name: '7-Day Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 7,
    durationHours: 168,
    durationLabel: '7 Days',
    price: 99,
    amountPaise: 9900,
    proTools: false,
    singleUse: false,
    badge: 'Weekly Pass',
    description: 'Basic map viewing valid for 7 full days from purchase'
  },
  'basic_1m': {
    id: 'basic_1m',
    name: 'Monthly Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 30,
    durationHours: 720,
    durationLabel: '1 Month',
    price: 299,
    amountPaise: 29900,
    proTools: false,
    singleUse: false,
    badge: 'Standard',
    description: 'Unlimited HD DP Map view for 30 days'
  },
  'basic_1y': {
    id: 'basic_1y',
    name: 'Annual Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 365,
    durationHours: 8760,
    durationLabel: '1 Year',
    price: 2499,
    amountPaise: 249900,
    proTools: false,
    singleUse: false,
    badge: 'Best Value',
    savings: 'Save ~30% · ~₹208/mo',
    description: 'Unlimited HD DP Map view for 1 full year'
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
  'pro_7d': {
    id: 'pro_7d',
    name: '7-Day Pro Pass',
    tier: 'pro',
    scope: 'pro',
    durationDays: 7,
    durationHours: 168,
    durationLabel: '7 Days',
    price: 249,
    amountPaise: 24900,
    proTools: true,
    singleUse: false,
    badge: 'Weekly Pro',
    description: 'Full GIS Pro measurement tools + DP view for 7 days'
  },
  'pro_1m': {
    id: 'pro_1m',
    name: 'Monthly Pro Pass',
    tier: 'pro',
    scope: 'pro',
    durationDays: 30,
    durationHours: 720,
    durationLabel: '1 Month',
    price: 599,
    amountPaise: 59900,
    proTools: true,
    singleUse: false,
    badge: 'Most Popular for Architects & Planners',
    savings: 'Best Seller',
    description: 'Full access to Polygon Area Measurement, GPS Coordinate Pinpoint & DP Maps for 30 days'
  },
  'pro_1y': {
    id: 'pro_1y',
    name: 'Annual Pro Pass',
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
    savings: '~₹500/mo · Full Pro All Year',
    description: 'Full 1-year unlimited GIS Pro access: Polygon Area, GPS Coordinates & all measurement tools'
  }
};

// =============================================================================
// AUTHORITATIVE FIRESTORE PRICING ENGINE & FAIL-SAFE FALLBACKS
// =============================================================================
const DEFAULT_PRICING_CONFIG = {
  trialOffer: {
    enabled: true,
    title: "7-Day Basic Access Trial Pass",
    price: 9,
    durationDays: 7,
    badge: "Special 3-day offer",
    daysRemaining: 3
  },
  tiers: {
    basic: {
      name: "Basic Map View",
      prices: { "1_day": 49, "7_days": 99, "30_days": 299, "365_days": 2499 }
    },
    pro: {
      name: "GIS Pro Tools (All-in-One)",
      prices: { "1_day": 99, "7_days": 249, "30_days": 599, "365_days": 5999 }
    }
  },
  features: {
    basic: ["Superimposed Sanctioned DP Maps", "High-Res Satellite Hybrid Imagery", "Sector & Locality Search"],
    pro: ["Road Distance Tracing", "Plot Polygon Area Measurement", "Lat/Lng Coordinate Jump & Pinpoint"]
  }
};

let cachedPricing = null;
let lastPricingFetch = 0;
const PRICING_CACHE_TTL = 30000; // 30 seconds in-memory cache

async function fetchAuthoritativePricing() {
  const now = Date.now();
  if (cachedPricing && (now - lastPricingFetch < PRICING_CACHE_TTL)) {
    return cachedPricing;
  }

  try {
    const firestoreUrl = 'https://firestore.googleapis.com/v1/projects/csmc-dp-portal/databases/(default)/documents/settings/pricing';
    const response = await fetch(firestoreUrl, { signal: AbortSignal.timeout(4000) });
    if (response.ok) {
      const data = await response.json();
      if (data && data.fields) {
        function unwrap(f) {
          if (!f) return null;
          if ('stringValue' in f) return f.stringValue;
          if ('integerValue' in f) return parseInt(f.integerValue, 10);
          if ('doubleValue' in f) return parseFloat(f.doubleValue);
          if ('booleanValue' in f) return f.booleanValue;
          if ('mapValue' in f) {
            const out = {};
            const fields = f.mapValue.fields || {};
            for (const k in fields) out[k] = unwrap(fields[k]);
            return out;
          }
          if ('arrayValue' in f) {
            return (f.arrayValue.values || []).map(unwrap);
          }
          return null;
        }
        const unwrapped = {};
        for (const k in data.fields) unwrapped[k] = unwrap(data.fields[k]);
        cachedPricing = { ...DEFAULT_PRICING_CONFIG, ...unwrapped };
        lastPricingFetch = now;
        return cachedPricing;
      }
    }
  } catch (err) {
    console.warn("Firestore pricing fetch warning (using default constants):", err.message);
  }

  return cachedPricing || DEFAULT_PRICING_CONFIG;
}

async function resolveAuthoritativePlan(planId, cadenceId) {
  const cfg = await fetchAuthoritativePricing();

  if (planId === 'launch_7d') {
    const trial = cfg.trialOffer || DEFAULT_PRICING_CONFIG.trialOffer;
    const price = trial.price !== undefined ? trial.price : 9;
    const durDays = trial.durationDays || 7;
    return {
      id: 'launch_7d',
      name: trial.title || 'Launch Special Trial',
      price: price,
      amountPaise: price * 100,
      durationDays: durDays,
      durationHours: durDays * 24,
      scope: 'basic',
      proTools: false,
      singleUse: true,
      trialEnabled: trial.enabled !== false
    };
  }

  let tier = 'basic';
  if (planId && (planId.startsWith('pro') || planId === 'pro')) {
    tier = 'pro';
  }

  let cadence = '30_days';
  if (cadenceId) {
    if (cadenceId === '1d') cadence = '1_day';
    else if (cadenceId === '7d') cadence = '7_days';
    else if (cadenceId === '1m') cadence = '30_days';
    else if (cadenceId === '1y') cadence = '365_days';
    else cadence = cadenceId;
  } else if (planId) {
    if (planId.includes('1d')) cadence = '1_day';
    else if (planId.includes('7d')) cadence = '7_days';
    else if (planId.includes('1m') || planId.includes('30d')) cadence = '30_days';
    else if (planId.includes('1y') || planId.includes('365d') || planId.includes('annual')) cadence = '365_days';
  }

  const tierPrices = (cfg.tiers && cfg.tiers[tier] && cfg.tiers[tier].prices) || DEFAULT_PRICING_CONFIG.tiers[tier].prices;
  const price = tierPrices[cadence] !== undefined ? tierPrices[cadence] : (tier === 'pro' ? 599 : 299);

  let days = 30;
  if (cadence === '1_day') days = 1;
  else if (cadence === '7_days') days = 7;
  else if (cadence === '30_days') days = 30;
  else if (cadence === '365_days') days = 365;

  const tierName = cfg.tiers?.[tier]?.name || (tier === 'pro' ? 'GIS Pro Tools (All-in-One)' : 'Basic Map View');
  const durLabel = days === 1 ? '1-Day' : (days === 7 ? '7-Day' : (days === 30 ? 'Monthly' : 'Annual'));
  const planKey = `${tier}_${days === 1 ? '1d' : (days === 7 ? '7d' : (days === 30 ? '1m' : '1y'))}`;

  return {
    id: planKey,
    name: `${durLabel} ${tierName}`,
    price: price,
    amountPaise: price * 100,
    durationDays: days,
    durationHours: days * 24,
    scope: tier,
    proTools: tier === 'pro',
    singleUse: false
  };
}

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

/**
 * Write verified subscription record to Firestore via Admin SDK.
 * This is the authoritative server-side write that syncs to the admin panel.
 */
async function writeSubscriptionToFirestore(subRecord, paymentId, phone, email) {
  if (!adminDb) {
    console.warn('[Firestore] Admin SDK not available — skipping server-side Firestore write');
    return;
  }

  try {
    const admin = require('firebase-admin');
    const recordWithTs = { ...subRecord, updatedAt: admin.firestore.FieldValue.serverTimestamp() };
    const batch = adminDb.batch();

    // 1. Audit ledger — immutable payment record keyed by payment ID
    if (paymentId) {
      batch.set(adminDb.collection('subscriptions').doc(paymentId), recordWithTs, { merge: true });
    }

    // 2. Active subscription profile keyed by phone or email with multi-tier stacking
    const targetDocId = (phone && phone.length === 10) ? phone : (email ? email.replace(/[@.]/g, '_') : null);
    if (targetDocId) {
      let mergedProfile = { ...recordWithTs };
      try {
        const existingDoc = await adminDb.collection('users_subscriptions').doc(targetDocId).get();
        if (existingDoc.exists) {
          const oldData = existingDoc.data() || {};
          const now = Date.now();

          const isNewPro = Boolean(subRecord.isPro || subRecord.scope === 'pro');
          const oldProExp = oldData.proExpiryTimestamp || (oldData.isPro && oldData.expiryTimestamp ? Number(oldData.expiryTimestamp) : 0);
          const oldBasicExp = oldData.basicExpiryTimestamp || (!oldData.isPro && oldData.expiryTimestamp ? Number(oldData.expiryTimestamp) : 0);

          let newProExp = isNewPro ? Number(subRecord.expiryTimestamp) : oldProExp;
          let newBasicExp = !isNewPro ? Number(subRecord.expiryTimestamp) : oldBasicExp;

          if (isNewPro && oldProExp > now) {
            newProExp = Math.max(oldProExp, Number(subRecord.expiryTimestamp));
          }
          if (!isNewPro && oldBasicExp > now) {
            newBasicExp = Math.max(oldBasicExp, Number(subRecord.expiryTimestamp));
          }

          const maxExp = Math.max(newProExp || 0, newBasicExp || 0, Number(subRecord.expiryTimestamp || 0));
          const totalPaid = Number(oldData.paidAmount || oldData.price || 0) + Number(subRecord.paidAmount || subRecord.price || 0);

          const hasActivePro = Boolean(newProExp && newProExp > now);
          const hasActiveBasic = Boolean(newBasicExp && newBasicExp > now);

          mergedProfile = {
            ...oldData,
            ...recordWithTs,
            paidAmount: totalPaid,
            price: totalPaid,
            proExpiryDate: newProExp ? new Date(newProExp).toISOString() : (oldData.proExpiryDate || null),
            proExpiryTimestamp: newProExp || null,
            basicExpiryDate: newBasicExp ? new Date(newBasicExp).toISOString() : (oldData.basicExpiryDate || null),
            basicExpiryTimestamp: newBasicExp || null,
            expiryTimestamp: maxExp,
            expiryDate: new Date(maxExp).toISOString(),
            planExpiry: new Date(maxExp).toISOString(),
            isPro: hasActivePro,
            proToolsEnabled: hasActivePro,
            role: hasActivePro ? 'pro' : (hasActiveBasic ? 'basic' : 'free'),
            scope: hasActivePro ? 'pro' : (hasActiveBasic ? 'basic' : 'basic'),
            planName: (hasActivePro && hasActiveBasic) ? `${subRecord.planName} (+ Active Basic)` : subRecord.planName
          };
        }
      } catch (mergeErr) {
        console.warn('[Firestore] Error merging stacked subscription profile:', mergeErr.message);
      }

      batch.set(adminDb.collection('users_subscriptions').doc(targetDocId), mergedProfile, { merge: true });
    }

    await batch.commit();
    console.log(`[Firestore] Subscription provisioned — payment: ${paymentId}, phone: ${phone || '(none)'}, email: ${email || '(none)'}`);
  } catch (err) {
    console.error('[Firestore] Batch write failed:', err.message);
  }
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
  const LAUNCH_OFFER_END_TIMESTAMP = new Date('2026-10-07T23:59:59+05:30').getTime();
  const isLaunchActive = Date.now() <= LAUNCH_OFFER_END_TIMESTAMP;
  const plansCopy = JSON.parse(JSON.stringify(SUBSCRIPTION_PLANS));
  if (!isLaunchActive && plansCopy['launch_7d']) {
    plansCopy['launch_7d'].available = false;
    plansCopy['launch_7d'].expired = true;
  }
  res.json({
    success: true,
    plans: plansCopy,
    launchOfferActive: isLaunchActive,
    timestamp: new Date().toISOString()
  });
});

// STEP 1: Create Order
// POST /api/create-order & POST /api/create-razorpay-order
// Server enforces plan pricing directly from Firestore; strictly prevents client-side price tampering
const handleCreateOrder = async (req, res) => {
  try {
    const { planId, cadenceId, userEmail, userPhone, userName, userCategory } = req.body;

    if (!planId) {
      return res.status(400).json({ error: "Missing required planId identifier." });
    }

    // Resolve authoritative server-side plan and tariff directly from Firestore settings/pricing
    const plan = await resolveAuthoritativePlan(planId, cadenceId);
    if (!plan) {
      return res.status(400).json({ error: "Invalid or unsupported plan identifier." });
    }

    // Strict Server-Side Tamper Prevention: Reject client attempts to pass custom amount differing from authoritative rate
    if (req.body.amount !== undefined) {
      const clientAmount = Number(req.body.amount);
      if (!isNaN(clientAmount) && clientAmount !== plan.amountPaise) {
        return res.status(400).json({
          error: "Price tampering detected. Authoritative tariffs are enforced directly from Firestore."
        });
      }
    }

    // Check if promotional trial offer is inactive in Firestore
    if (plan.id === 'launch_7d' && plan.trialEnabled === false) {
      return res.status(400).json({
        error: "The promotional trial offer is currently inactive. Please choose a standard pass."
      });
    }

    if (!key_id || !key_secret) {
      return res.status(500).json({ error: "Payment processor credentials not configured on server." });
    }

    // Enforce canonical amount strictly from authoritative pricing
    const targetAmount = plan.amountPaise;

    // Sanitize and normalize metadata fields
    const sanitizedEmail = String(userEmail || '').trim().toLowerCase().slice(0, 120);
    const sanitizedPhone = normalizeIndianPhone(userPhone);
    const sanitizedName = String(userName || 'Citizen User').slice(0, 80);
    const sanitizedCat = String(userCategory || 'Individual Citizen').slice(0, 80);

    // Strict Single-Use Trial Pass Enforcement
    if (plan.id === 'launch_7d') {
      if (!sanitizedPhone || sanitizedPhone.length !== 10 || !/^[6-9]\d{9}$/.test(sanitizedPhone)) {
        return res.status(400).json({
          error: "A valid 10-digit Indian mobile number (starting with 6-9) is required to claim the single-use trial offer."
        });
      }
      if (CLAIMED_TRIAL_PHONES.has(sanitizedPhone)) {
        return res.status(400).json({
          error: "This mobile number has already redeemed the introductory trial pass. Please choose a standard pass."
        });
      }
    }

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
        durationDays: String(plan.durationDays),
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
};

app.post('/api/create-order', handleCreateOrder);
app.post('/api/create-razorpay-order', handleCreateOrder);

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

    // Cache verified subscription record in memory
    const userEmail = String(req.body.userEmail || '').trim().toLowerCase();
    const userPhone = normalizeIndianPhone(req.body.userPhone);
    const userName = String(req.body.userName || '').trim().slice(0, 80) || (userEmail ? userEmail.split('@')[0] : 'Pass Holder');

    // Atomic Single-Use Trial Phone Enforcement
    if (plan.id === 'launch_7d' && userPhone) {
      CLAIMED_TRIAL_PHONES.add(userPhone);
    }

    const isProTier = Boolean(plan.proTools || plan.scope === 'pro');
    const isBasicTier = Boolean(!isProTier);

    VERIFIED_SUBSCRIPTIONS.set(paymentId, {
      isSubscribed: true,
      role: isProTier ? 'pro' : 'basic',
      tier: isProTier ? 'pro' : 'basic',
      isPro: isProTier,
      isBasic: isBasicTier,
      planId: plan.id,
      planName: plan.name,
      scope: plan.scope,
      proToolsEnabled: Boolean(plan.proTools),
      price: plan.price,
      purchaseTimestamp: now,
      expiryTimestamp: expiryTimestamp,
      expiryDate: new Date(expiryTimestamp).toISOString(),
      paymentId: paymentId,
      orderId: orderId,
      email: userEmail,
      phone: userPhone,
      name: userName
    });

    // ====================================================================
    // SERVER-SIDE FIRESTORE WRITE (Authoritative — survives server restarts)
    // ====================================================================
    const fsRecord = {
      isSubscribed: true,
      isProvisioned: true,
      role: isProTier ? 'pro' : 'basic',
      tier: isProTier ? 'pro' : 'basic',
      isPro: isProTier,
      isBasic: isBasicTier,
      proToolsEnabled: Boolean(plan.proTools),
      scope: plan.scope || 'basic',
      planId: plan.id,
      planName: plan.name,
      price: plan.price,
      paidAmount: plan.price,
      planExpiry: new Date(expiryTimestamp).toISOString(),
      purchaseTimestamp: now,
      purchaseDate: new Date(now).toISOString(),
      expiryTimestamp: expiryTimestamp,
      expiryDate: new Date(expiryTimestamp).toISOString(),
      paymentId: paymentId,
      orderId: orderId,
      phone: userPhone,
      email: userEmail,
      name: userName,
      category: String(req.body.userCategory || 'Individual Citizen / Land Buyer').slice(0, 80),
      hasUsedLaunchOffer: (plan.id === 'launch_7d')
    };

    // Fire-and-forget (don't await — response already sent)
    writeSubscriptionToFirestore(fsRecord, paymentId, userPhone, userEmail).catch(e =>
      console.warn('[Firestore] Background write error:', e.message)
    );

    res.status(200).json({
      success: true,
      message: "Payment signature verified successfully",
      order_id: orderId,
      payment_id: paymentId,
      planId: plan.id,
      planName: plan.name,
      scope: plan.scope,
      tier: isProTier ? 'pro' : 'basic',
      role: isProTier ? 'pro' : 'basic',
      isPro: isProTier,
      isBasic: isBasicTier,
      proToolsEnabled: Boolean(plan.proTools),
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
      if (pid) {
        PROCESSED_PAYMENTS.set(pid, Date.now());
        const phone = normalizeIndianPhone(notes.userPhone || paymentEntity.contact);
        const email = String(notes.userEmail || paymentEntity.email || '').toLowerCase().trim();
        const name = String(notes.userName || 'Citizen User').slice(0, 80);
        const category = String(notes.userCategory || notes.category || 'Individual Citizen / Land Buyer').slice(0, 80);
        const orderId = String(paymentEntity.order_id || '').trim();
        const amountRupees = Number(paymentEntity.amount || 0) / 100;
        if (notes.planId === 'launch_7d' && phone) {
          CLAIMED_TRIAL_PHONES.add(phone);
        }

        // Webhook Firestore write
        const wPlanId = (notes.planId && SUBSCRIPTION_PLANS[notes.planId]) ? notes.planId : 'basic_1m';
        const wPlan = SUBSCRIPTION_PLANS[wPlanId];
        const wNow = Date.now();
        const wExpiry = wPlan.durationHours === 24
          ? wNow + (24 * 60 * 60 * 1000)
          : wNow + ((wPlan.durationDays || 30) * 24 * 60 * 60 * 1000);
        const isProW = Boolean(wPlan.proTools || wPlan.scope === 'pro');

        const wRecord = {
          isSubscribed: true,
          isProvisioned: true,
          role: isProW ? 'pro' : 'basic',
          tier: isProW ? 'pro' : 'basic',
          isPro: isProW,
          isBasic: !isProW,
          proToolsEnabled: Boolean(wPlan.proTools),
          scope: wPlan.scope || 'basic',
          planId: wPlanId,
          planName: notes.planName || wPlanId,
          price: amountRupees,
          paidAmount: amountRupees,
          planExpiry: new Date(wExpiry).toISOString(),
          purchaseTimestamp: wNow,
          purchaseDate: new Date(wNow).toISOString(),
          expiryTimestamp: wExpiry,
          expiryDate: new Date(wExpiry).toISOString(),
          paymentId: pid,
          orderId: orderId,
          phone: phone,
          email: email,
          name: name,
          category: category,
          hasUsedLaunchOffer: (wPlanId === 'launch_7d')
        };

        writeSubscriptionToFirestore(wRecord, pid, phone, email).catch(e =>
          console.warn('[Webhook Firestore] Write error:', e.message)
        );
      }
      console.log(`[AUDIT] Webhook confirmed payment ${pid}, Plan: ${notes.planId}`);
    }

    res.status(200).json({ status: "ok", received: true });
  } catch (err) {
    console.error("Webhook processing error:", err.message || err);
    res.status(500).json({ error: "Webhook processing failed." });
  }
});

// STEP 4: Subscription Lookup & Pass Restoration Endpoint
// Hardened with strict ownership verification: Payment ID alone CANNOT unlock a pass.
function inferPlanFromPayment(p) {
  const planIdFromNotes = p.notes && p.notes.planId;
  if (planIdFromNotes && SUBSCRIPTION_PLANS[planIdFromNotes]) {
    return SUBSCRIPTION_PLANS[planIdFromNotes];
  }
  const amt = p.amount ? p.amount / 100 : 0;
  if (amt === 9) return SUBSCRIPTION_PLANS['launch_7d'];
  if (amt === 49) return SUBSCRIPTION_PLANS['basic_1d'];
  if (amt === 99) return SUBSCRIPTION_PLANS['pro_1d'];
  if (amt === 249) return SUBSCRIPTION_PLANS['basic_1m'];
  if (amt === 499) return SUBSCRIPTION_PLANS['pro_1m'];
  if (amt === 1999) return SUBSCRIPTION_PLANS['basic_1y'];
  if (amt === 3999) return SUBSCRIPTION_PLANS['pro_1y'];
  // Fallbacks for legacy payments
  if (amt === 299) return SUBSCRIPTION_PLANS['basic_1m'];
  if (amt === 599) return SUBSCRIPTION_PLANS['pro_1m'];
  if (amt === 2999) return SUBSCRIPTION_PLANS['basic_1y'];
  if (amt === 5999) return SUBSCRIPTION_PLANS['pro_1y'];
  return SUBSCRIPTION_PLANS['basic_1m'];
}

function calculateExpiry(p, plan) {
  const purchaseMs = (p.created_at || Math.floor(Date.now() / 1000)) * 1000;
  if (plan.durationHours === 24) {
    return purchaseMs + (24 * 60 * 60 * 1000);
  }
  return purchaseMs + ((plan.durationDays || 30) * 24 * 60 * 60 * 1000);
}

async function handleSubscriptionLookup(req, res) {
  try {
    const params = req.method === 'GET' ? req.query : req.body;
    let rawEmail = String(params.email || '').trim().toLowerCase().slice(0, 120);
    let rawPhone = normalizeIndianPhone(params.phone);
    let rawPayId = String(params.paymentId || params.payId || '').trim().slice(0, 80);

    // If paymentId was mistakenly passed in email field (e.g. pay_...)
    if (rawEmail.startsWith('pay_')) {
      rawPayId = rawEmail;
      rawEmail = '';
    } else if (rawEmail.replace(/\D/g, '').length >= 10 && !rawEmail.includes('@')) {
      rawPhone = normalizeIndianPhone(rawEmail);
      rawEmail = '';
    }

    // SECURITY HARDENING: Entering a Payment ID alone CANNOT unlock a pass without verifying
    // matching ownership (via phone/email) to prevent guessing/brute-forcing payment identifiers.
    if (!rawPayId && !rawEmail && !rawPhone) {
      return res.status(400).json({
        success: false,
        found: false,
        error: "Please provide your registered email or phone number and Payment ID."
      });
    }

    if (rawPayId && !rawEmail && !rawPhone) {
      return res.status(400).json({
        success: false,
        found: false,
        error: "Ownership verification required: To restore access via Payment ID, you must also provide the registered email address or mobile number used during purchase."
      });
    }

    if (!rawPayId && (rawEmail || rawPhone)) {
      return res.status(400).json({
        success: false,
        found: false,
        error: "To restore access to your pass, please provide your Razorpay Payment ID along with your registered email or mobile number."
      });
    }

    if (!key_id || !key_secret) {
      return res.status(500).json({
        success: false,
        error: "Payment processor credentials not configured on server."
      });
    }

    const candidates = [];
    const now = Date.now();

    // 1. Check in-memory verified subscriptions cache with strict ownership match
    for (const sub of VERIFIED_SUBSCRIPTIONS.values()) {
      const emailMatch = rawEmail && rawEmail.includes('@') && sub.email && (sub.email === rawEmail || sub.email.includes(rawEmail));
      const phoneMatch = rawPhone && rawPhone.length === 10 && sub.phone && (sub.phone === rawPhone || sub.phone.endsWith(rawPhone));
      const payMatch = rawPayId && sub.paymentId === rawPayId;

      if (payMatch && (emailMatch || phoneMatch)) {
        const plan = SUBSCRIPTION_PLANS[sub.planId] || { id: sub.planId, name: sub.planName, scope: sub.scope, proTools: sub.proToolsEnabled, price: sub.price };
        candidates.push({
          plan,
          expiryTimestamp: sub.expiryTimestamp,
          isExpired: now >= sub.expiryTimestamp,
          purchaseTimestamp: sub.purchaseTimestamp,
          paymentId: sub.paymentId,
          orderId: sub.orderId,
          email: sub.email,
          phone: sub.phone,
          name: sub.name
        });
      }
    }

    // 2. Direct fetch from Razorpay API with strict ownership match
    if (rawPayId && rawPayId.startsWith('pay_')) {
      try {
        const p = await razorpay.payments.fetch(rawPayId);
        if (p && (p.status === 'captured' || p.status === 'authorized')) {
          const pEmail = String(p.email || p.notes?.userEmail || '').trim().toLowerCase();
          const pPhone = normalizeIndianPhone(p.contact || p.notes?.userPhone);

          const emailMatch = rawEmail && rawEmail.includes('@') && (pEmail === rawEmail || (rawEmail.length >= 5 && pEmail.includes(rawEmail)));
          const phoneMatch = rawPhone && rawPhone.length === 10 && (pPhone === rawPhone || pPhone.endsWith(rawPhone));

          if (emailMatch || phoneMatch) {
            const plan = inferPlanFromPayment(p);
            const expiry = calculateExpiry(p, plan);
            candidates.push({
              plan,
              expiryTimestamp: expiry,
              isExpired: now >= expiry,
              purchaseTimestamp: p.created_at * 1000,
              paymentId: p.id,
              orderId: p.order_id,
              email: pEmail,
              phone: pPhone,
              name: p.notes?.userName || (pEmail ? pEmail.split('@')[0] : 'Pass Holder')
            });
          }
        }
      } catch (fetchErr) {
        console.warn("Direct payment fetch notice:", fetchErr.message);
      }
    }

    // 3. Scan recent Razorpay payments (last 100) with strict dual-match
    try {
      const paymentList = await razorpay.payments.all({ count: 100 });
      if (paymentList && Array.isArray(paymentList.items)) {
        for (const p of paymentList.items) {
          if (p.status !== 'captured' && p.status !== 'authorized') continue;

          const pEmail = String(p.email || '').trim().toLowerCase();
          const pNotesEmail = String(p.notes?.userEmail || p.notes?.email || '').trim().toLowerCase();
          const pPhone = normalizeIndianPhone(p.contact);
          const pNotesPhone = normalizeIndianPhone(p.notes?.userPhone || p.notes?.phone);
          const pId = String(p.id || '').trim();

          const emailMatch = rawEmail && rawEmail.includes('@') && (
            pEmail === rawEmail ||
            pNotesEmail === rawEmail ||
            (rawEmail.length >= 5 && pEmail.includes(rawEmail)) ||
            (rawEmail.length >= 5 && pNotesEmail.includes(rawEmail))
          );
          const phoneMatch = rawPhone && rawPhone.length === 10 && (
            pPhone === rawPhone ||
            pNotesPhone === rawPhone
          );
          const payMatch = rawPayId && pId === rawPayId;

          // STRICT CHECK: Both payment ID and verified email/phone must match!
          if (payMatch && (emailMatch || phoneMatch)) {
            if (!candidates.some(c => c.paymentId === p.id)) {
              const plan = inferPlanFromPayment(p);
              const expiry = calculateExpiry(p, plan);
              candidates.push({
                plan,
                expiryTimestamp: expiry,
                isExpired: now >= expiry,
                purchaseTimestamp: p.created_at * 1000,
                paymentId: p.id,
                orderId: p.order_id,
                email: p.email || p.notes?.userEmail || rawEmail,
                phone: pPhone || rawPhone,
                name: p.notes?.userName || (p.email ? p.email.split('@')[0] : 'Pass Holder')
              });
            }
          }
        }
      }
    } catch (rzpErr) {
      console.warn("Razorpay payments scan notice:", rzpErr.message);
    }

    if (candidates.length === 0) {
      return res.status(200).json({
        success: false,
        found: false,
        message: "No subscription record found matching the provided details."
      });
    }

    // Sort: latest expiry first
    candidates.sort((a, b) => b.expiryTimestamp - a.expiryTimestamp);

    // Pick active candidate if exists, else latest
    const activeCandidate = candidates.find(c => !c.isExpired);
    if (activeCandidate) {
      return res.status(200).json({
        success: true,
        found: true,
        active: true,
        subscription: {
          isSubscribed: true,
          planId: activeCandidate.plan.id,
          planName: activeCandidate.plan.name,
          scope: activeCandidate.plan.scope,
          proToolsEnabled: Boolean(activeCandidate.plan.proTools),
          price: activeCandidate.plan.price,
          purchaseTimestamp: activeCandidate.purchaseTimestamp,
          purchaseDate: new Date(activeCandidate.purchaseTimestamp).toISOString(),
          expiryTimestamp: activeCandidate.expiryTimestamp,
          expiryDate: new Date(activeCandidate.expiryTimestamp).toISOString(),
          paymentId: activeCandidate.paymentId,
          orderId: activeCandidate.orderId,
          email: activeCandidate.email,
          phone: activeCandidate.phone,
          name: activeCandidate.name
        }
      });
    } else {
      const latest = candidates[0];
      const expFormatted = new Date(latest.expiryTimestamp).toLocaleDateString('en-IN');
      return res.status(200).json({
        success: false,
        found: true,
        expired: true,
        planName: latest.plan.name,
        expiryTimestamp: latest.expiryTimestamp,
        expiryDate: new Date(latest.expiryTimestamp).toISOString(),
        expiryFormatted: expFormatted,
        message: `Subscription record found for ${latest.name || latest.email}, but it expired on ${expFormatted}. Please purchase a new pass.`
      });
    }
  } catch (err) {
    console.error("Lookup subscription internal error:", err);
    res.status(500).json({
      success: false,
      error: "Internal error checking subscription."
    });
  }
}

app.post('/api/lookup-subscription', handleSubscriptionLookup);
app.get('/api/lookup-subscription', handleSubscriptionLookup);

// =============================================================================
// ADMIN: RAZORPAY → FIRESTORE RECONCILIATION ENDPOINT
// POST /api/admin-reconcile
// Scans Razorpay payment history and provisions any captured payments
// that are missing from Firestore's users_subscriptions collection.
// This fixes users who paid before the Firestore write bug was patched.
// =============================================================================
app.post('/api/admin-reconcile', async (req, res) => {
  // Simple admin key guard — upgrade to proper admin auth in production
  const ADMIN_RECONCILE_KEY = process.env.ADMIN_RECONCILE_KEY || 'csmc_admin_reconcile_2024';
  const { adminKey } = req.body;
  if (adminKey !== ADMIN_RECONCILE_KEY) {
    return res.status(403).json({ error: 'Unauthorized: invalid admin key.' });
  }

  if (!adminDb) {
    return res.status(503).json({
      error: 'Firestore Admin SDK not initialized. Please set FIREBASE_SERVICE_ACCOUNT env var on Render and redeploy.',
      hint: 'Go to Render dashboard → csmc-dp-backend → Environment → Add FIREBASE_SERVICE_ACCOUNT as the JSON content of your Firebase service account key.'
    });
  }

  if (!key_id || !key_secret) {
    return res.status(503).json({ error: 'Razorpay credentials not configured.' });
  }

  let synced = 0;
  let skipped = 0;
  let errors = 0;
  let total = 0;
  const results = [];

  try {
    const limit = Math.min(Math.max(parseInt(req.body.limit, 10) || 50, 1), 100);
    // Fetch last payments from Razorpay
    let payments = [];
    try {
      const page = await razorpay.payments.all({ count: limit, skip: 0 });
      if (page && Array.isArray(page.items)) {
        payments = page.items;
      }
    } catch (fetchErr) {
      const msg = fetchErr.error?.description || fetchErr.message || 'Razorpay payments fetch failed';
      console.error('[Admin Reconcile] Razorpay error:', msg);
      return res.status(500).json({ success: false, error: msg });
    }

    const validPayments = payments.filter(p => p.status === 'captured' || p.status === 'authorized');
    total = validPayments.length;

    // Process in batches of 10 concurrent requests to prevent timeout
    const BATCH_SIZE = 10;
    for (let i = 0; i < validPayments.length; i += BATCH_SIZE) {
      const chunk = validPayments.slice(i, i + BATCH_SIZE);
      await Promise.all(chunk.map(async (p) => {
        const pid = p.id;
        const notes = p.notes || {};
        const phone = normalizeIndianPhone(notes.userPhone || notes.phone || p.contact);
        const email = String(notes.userEmail || notes.email || p.email || '').toLowerCase().trim();
        const name = String(notes.userName || notes.name || (email ? email.split('@')[0] : 'Citizen User')).slice(0, 80);
        const category = String(notes.userCategory || notes.category || 'Individual Citizen / Land Buyer').slice(0, 80);

        const planId = (notes.planId && SUBSCRIPTION_PLANS[notes.planId]) ? notes.planId : inferPlanFromPayment(p)?.id || 'basic_1m';
        const plan = SUBSCRIPTION_PLANS[planId] || SUBSCRIPTION_PLANS['basic_1m'];

        const purchaseMs = (p.created_at || Math.floor(Date.now() / 1000)) * 1000;
        let expiryTimestamp;
        if (plan.durationHours === 24) {
          expiryTimestamp = purchaseMs + (24 * 60 * 60 * 1000);
        } else {
          expiryTimestamp = purchaseMs + ((plan.durationDays || 30) * 24 * 60 * 60 * 1000);
        }

        const isProTier = Boolean(plan.proTools || plan.scope === 'pro');
        const amountRupees = Number(p.amount || 0) / 100;

        const subRecord = {
          isSubscribed: true,
          isProvisioned: true,
          role: isProTier ? 'pro' : 'basic',
          tier: isProTier ? 'pro' : 'basic',
          isPro: isProTier,
          isBasic: !isProTier,
          proToolsEnabled: Boolean(plan.proTools),
          scope: plan.scope || 'basic',
          planId,
          planName: notes.planName || plan.name || planId,
          price: amountRupees,
          paidAmount: amountRupees,
          planExpiry: new Date(expiryTimestamp).toISOString(),
          purchaseTimestamp: purchaseMs,
          purchaseDate: new Date(purchaseMs).toISOString(),
          expiryTimestamp,
          expiryDate: new Date(expiryTimestamp).toISOString(),
          paymentId: pid,
          orderId: p.order_id || '',
          phone,
          email,
          name,
          category,
          hasUsedLaunchOffer: (planId === 'launch_7d'),
          reconciledAt: new Date().toISOString(),
          reconcileSource: 'admin-reconcile-endpoint'
        };

        // Attempt Firestore persistence (gracefully handles Spark tier quota limits)
        let writeStatus = 'synced';
        try {
          const existingDoc = await adminDb.collection('subscriptions').doc(pid).get();
          if (existingDoc.exists && existingDoc.data().isProvisioned) {
            skipped++;
            results.push({ ...subRecord, status: 'already_provisioned' });
            return;
          }
          await writeSubscriptionToFirestore(subRecord, pid, phone, email);
          synced++;
        } catch (fsErr) {
          const isQuota = (fsErr.message || '').includes('RESOURCE_EXHAUSTED') || (fsErr.code === 8);
          writeStatus = isQuota ? 'quota_exceeded' : 'write_failed';
          errors++;
          console.warn(`[Reconcile] Firestore operation failed for ${pid}:`, fsErr.message);
        }

        results.push({ ...subRecord, status: writeStatus });
      }));
    }

    const quotaExceeded = results.some(r => r.status === 'quota_exceeded');
    console.log(`[Admin Reconcile] Done: ${synced} synced, ${skipped} skipped, ${errors} errors out of ${total} total (quotaExceeded: ${quotaExceeded})`);
    return res.status(200).json({ success: true, synced, skipped, errors, total, quotaExceeded, results });
  } catch (err) {
    const errMsg = err.error?.description || err.message || String(err);
    console.error('[Admin Reconcile] Fatal error:', errMsg);
    return res.status(500).json({ success: false, error: errMsg });
});

// =============================================================================
// ADMIN: PUBLISH DYNAMIC PRICING ENDPOINT
// POST /api/admin-pricing
// Updates in-memory plans and syncs to settings/pricing in Firestore via Admin SDK.
// =============================================================================
app.post('/api/admin-pricing', async (req, res) => {
  const ADMIN_RECONCILE_KEY = process.env.ADMIN_RECONCILE_KEY || 'csmc_admin_reconcile_2024';
  const { adminKey, pricing } = req.body;
  if (adminKey !== ADMIN_RECONCILE_KEY) {
    return res.status(403).json({ error: 'Unauthorized: invalid admin key.' });
  }
  if (!pricing) {
    return res.status(400).json({ error: 'Pricing payload required.' });
  }

  try {
    // Update in-memory plans if tiers are provided
    if (pricing.tiers) {
      const basicPrices = pricing.tiers.basic?.prices || {};
      const proPrices = pricing.tiers.pro?.prices || {};

      if (SUBSCRIPTION_PLANS['basic_1d'] && basicPrices['1_day']) {
        SUBSCRIPTION_PLANS['basic_1d'].price = basicPrices['1_day'];
        SUBSCRIPTION_PLANS['basic_1d'].amountPaise = basicPrices['1_day'] * 100;
      }
      if (SUBSCRIPTION_PLANS['basic_7d'] && basicPrices['7_days']) {
        SUBSCRIPTION_PLANS['basic_7d'].price = basicPrices['7_days'];
        SUBSCRIPTION_PLANS['basic_7d'].amountPaise = basicPrices['7_days'] * 100;
      }
      if (SUBSCRIPTION_PLANS['basic_1m'] && basicPrices['30_days']) {
        SUBSCRIPTION_PLANS['basic_1m'].price = basicPrices['30_days'];
        SUBSCRIPTION_PLANS['basic_1m'].amountPaise = basicPrices['30_days'] * 100;
      }
      if (SUBSCRIPTION_PLANS['basic_1y'] && basicPrices['365_days']) {
        SUBSCRIPTION_PLANS['basic_1y'].price = basicPrices['365_days'];
        SUBSCRIPTION_PLANS['basic_1y'].amountPaise = basicPrices['365_days'] * 100;
      }

      if (SUBSCRIPTION_PLANS['pro_1d'] && proPrices['1_day']) {
        SUBSCRIPTION_PLANS['pro_1d'].price = proPrices['1_day'];
        SUBSCRIPTION_PLANS['pro_1d'].amountPaise = proPrices['1_day'] * 100;
      }
      if (SUBSCRIPTION_PLANS['pro_7d'] && proPrices['7_days']) {
        SUBSCRIPTION_PLANS['pro_7d'].price = proPrices['7_days'];
        SUBSCRIPTION_PLANS['pro_7d'].amountPaise = proPrices['7_days'] * 100;
      }
      if (SUBSCRIPTION_PLANS['pro_1m'] && proPrices['30_days']) {
        SUBSCRIPTION_PLANS['pro_1m'].price = proPrices['30_days'];
        SUBSCRIPTION_PLANS['pro_1m'].amountPaise = proPrices['30_days'] * 100;
      }
      if (SUBSCRIPTION_PLANS['pro_1y'] && proPrices['365_days']) {
        SUBSCRIPTION_PLANS['pro_1y'].price = proPrices['365_days'];
        SUBSCRIPTION_PLANS['pro_1y'].amountPaise = proPrices['365_days'] * 100;
      }
    }
    if (pricing.trialOffer && pricing.trialOffer.price && SUBSCRIPTION_PLANS['launch_7d']) {
      SUBSCRIPTION_PLANS['launch_7d'].price = pricing.trialOffer.price;
      SUBSCRIPTION_PLANS['launch_7d'].amountPaise = pricing.trialOffer.price * 100;
    }

    // Save to Firestore via Admin SDK if available
    let firestoreSaved = false;
    if (adminDb) {
      try {
        await adminDb.collection('settings').doc('pricing').set(pricing, { merge: true });
        firestoreSaved = true;
      } catch (fsErr) {
        console.warn('[Admin Pricing] Firestore write failed:', fsErr.message);
      }
    }

    return res.json({ success: true, firestoreSaved, plansCount: Object.keys(SUBSCRIPTION_PLANS).length });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});


// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: "healthy",
    service: "CSMC Razorpay API",
    firebaseAdmin: Boolean(adminDb),
    plansCount: Object.keys(SUBSCRIPTION_PLANS).length,
    timestamp: new Date().toISOString()
  });
});

// Root endpoint: API Status & Directory
app.get('/', (req, res) => {
  res.json({
    status: "online",
    service: "CSMC DP Spatial Portal Payment API",
    endpoints: [
      "POST /api/create-order",
      "POST /api/verify-payment",
      "POST /api/lookup-subscription",
      "GET /api/lookup-subscription",
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
