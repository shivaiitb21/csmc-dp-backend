require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname)));

// Razorpay Instance
const key_id = process.env.RAZORPAY_KEY_ID;
const key_secret = process.env.RAZORPAY_KEY_SECRET;
const webhook_secret = process.env.RAZORPAY_WEBHOOK_SECRET || process.env.RAZORPAY_KEY_SECRET;

if (!key_id || !key_secret) {
  console.warn("WARNING: RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET not set in environment variables!");
}

const razorpay = new Razorpay({
  key_id: key_id || '',
  key_secret: key_secret || ''
});

// Official Subscription Pricing Matrix
const SUBSCRIPTION_PLANS = {
  // Launch Offer (One-Time Trial)
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
  // Basic View Tiers
  'basic_1d': {
    id: 'basic_1d',
    name: '1-Day Basic Pass',
    tier: 'basic',
    scope: 'basic',
    durationDays: 1,
    durationHours: 24, // Strictly 24 hours
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
  // Pro Tools Tiers
  'pro_1d': {
    id: 'pro_1d',
    name: '1-Day Pro Pass',
    tier: 'pro',
    scope: 'pro',
    durationDays: 1,
    durationHours: 24, // Strictly 24 hours
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

// Endpoint to fetch public key for frontend (Never exposes secret)
app.get('/api/razorpay-key', (req, res) => {
  if (!process.env.RAZORPAY_KEY_ID) {
    return res.status(500).json({ error: "Razorpay Key ID not configured on server" });
  }
  res.json({ key_id: process.env.RAZORPAY_KEY_ID });
});

// Endpoint to fetch active subscription plans schema
app.get('/api/subscription-plans', (req, res) => {
  res.json({
    success: true,
    plans: SUBSCRIPTION_PLANS,
    timestamp: new Date().toISOString()
  });
});

// STEP 1: BACKEND - Create Order
// POST /api/create-order
// Request: { amount (in paise), currency, receipt, planId, userEmail, userPhone }
// Return: { order_id, amount, currency, plan_id }
app.post('/api/create-order', async (req, res) => {
  try {
    const { amount, currency = 'INR', receipt = `rcpt_${Date.now()}`, planId, userEmail, userPhone } = req.body;

    let targetAmount = parseInt(amount, 10);

    // If planId provided, strictly validate amount against verified pricing matrix
    if (planId && SUBSCRIPTION_PLANS[planId]) {
      targetAmount = SUBSCRIPTION_PLANS[planId].amountPaise;
    }

    // Validate amount >= 100 paise (₹1.00)
    if (!targetAmount || isNaN(targetAmount) || targetAmount < 100) {
      return res.status(400).json({
        error: "Invalid amount. Minimum amount must be at least 100 paise (₹1.00)."
      });
    }

    if (!key_id || !key_secret) {
      return res.status(401).json({
        error: "Razorpay credentials missing on server."
      });
    }

    const plan = planId ? SUBSCRIPTION_PLANS[planId] : null;

    const options = {
      amount: targetAmount,
      currency: currency || 'INR',
      receipt: receipt || `rcpt_${Date.now()}`,
      payment_capture: 1,
      notes: {
        portal: 'CSMC DP Spatial Portal',
        planId: planId || 'custom',
        planName: plan ? plan.name : 'Subscription Plan',
        scope: plan ? plan.scope : 'basic',
        userEmail: userEmail || '',
        userPhone: userPhone || '',
        createdAt: new Date().toISOString()
      }
    };

    const order = await razorpay.orders.create(options);
    if (!order || !order.id) {
      return res.status(500).json({ error: "Failed to create order with Razorpay" });
    }

    res.status(200).json({
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      plan_id: planId || null
    });
  } catch (error) {
    console.error("Error creating Razorpay order:", error);
    if (error.statusCode === 401 || error.code === 'BAD_REQUEST_ERROR') {
      return res.status(error.statusCode || 401).json({
        error: error.description || error.message || "Razorpay authentication failed"
      });
    }
    res.status(500).json({
      error: error.description || error.message || "Failed to create Razorpay order"
    });
  }
});

// STEP 3: BACKEND - Verify Signature
// POST /api/verify-payment
// Algorithm: HMAC-SHA256(order_id + "|" + payment_id, KEY_SECRET)
app.post('/api/verify-payment', (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, planId, userEmail } = req.body;

    // Missing fields validation
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        success: false,
        error: "Missing required payment parameters (razorpay_order_id, razorpay_payment_id, razorpay_signature required)"
      });
    }

    if (!key_secret) {
      return res.status(500).json({
        success: false,
        error: "Server configuration error: Key Secret not configured"
      });
    }

    // Algorithm: HMAC-SHA256(order_id + "|" + payment_id, KEY_SECRET)
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', key_secret)
      .update(body.toString())
      .digest('hex');

    // Compare signatures securely
    const isAuthentic = (expectedSignature === razorpay_signature);

    if (isAuthentic) {
      const plan = (planId && SUBSCRIPTION_PLANS[planId]) ? SUBSCRIPTION_PLANS[planId] : null;
      const now = Date.now();
      let expiryTimestamp = now + (30 * 24 * 60 * 60 * 1000); // default 30 days

      if (plan) {
        if (plan.durationHours === 24) {
          // Strictly 24 hours from purchase timestamp
          expiryTimestamp = now + (24 * 60 * 60 * 1000);
        } else {
          expiryTimestamp = now + (plan.durationDays * 24 * 60 * 60 * 1000);
        }
      }

      return res.status(200).json({
        success: true,
        message: "Payment signature verified successfully",
        order_id: razorpay_order_id,
        payment_id: razorpay_payment_id,
        planId: planId || null,
        planName: plan ? plan.name : 'Subscription',
        scope: plan ? plan.scope : 'basic',
        proToolsEnabled: plan ? plan.proTools : false,
        purchaseTimestamp: now,
        expiryTimestamp: expiryTimestamp,
        expiryDate: new Date(expiryTimestamp).toISOString()
      });
    } else {
      // Signature mismatch: return 400, do NOT mark as paid
      return res.status(400).json({
        success: false,
        error: "Payment verification failed: Signature mismatch"
      });
    }
  } catch (error) {
    console.error("Error verifying Razorpay signature:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error during payment verification"
    });
  }
});

// STEP 4: BACKEND - Razorpay Webhook Handler
// POST /api/razorpay-webhook
// Validates signature and handles server-to-server payment updates
app.post('/api/razorpay-webhook', (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature) {
      return res.status(400).json({ error: "Missing x-razorpay-signature header" });
    }

    const payload = JSON.stringify(req.body);
    const expectedSignature = crypto
      .createHmac('sha256', webhook_secret || key_secret)
      .update(payload)
      .digest('hex');

    if (expectedSignature !== signature) {
      console.warn("⚠️ Webhook signature mismatch from IP:", req.ip);
      return res.status(400).json({ error: "Invalid webhook signature" });
    }

    const event = req.body.event;
    console.log(`🔔 Razorpay Webhook received event: ${event}`);

    // Process event types
    if (event === 'order.paid' || event === 'payment.captured') {
      const paymentEntity = req.body.payload?.payment?.entity;
      const notes = paymentEntity?.notes || {};
      console.log(`✅ Webhook verified payment ID: ${paymentEntity?.id}, Amount: ₹${(paymentEntity?.amount || 0) / 100}, Plan: ${notes.planId}`);
    }

    res.status(200).json({ status: "ok", received: true });
  } catch (err) {
    console.error("Webhook processing error:", err);
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

// Health check route
app.get('/health', (req, res) => {
  res.json({
    status: "healthy",
    service: "CSMC Razorpay API",
    plansCount: Object.keys(SUBSCRIPTION_PLANS).length,
    timestamp: new Date().toISOString()
  });
});

// Root route: Serve frontend if present, otherwise return API status
app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  const fs = require('fs');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
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

// Start Server if run directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`CSMC Spatial Portal Server running on http://localhost:${PORT}`);
    console.log(`Razorpay Key ID configured: ${key_id ? key_id.substring(0, 8) + '...' : 'NONE'}`);
  });
}

module.exports = app;
