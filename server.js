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

if (!key_id || !key_secret) {
  console.warn("WARNING: RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET not set in environment variables!");
}

const razorpay = new Razorpay({
  key_id: key_id || '',
  key_secret: key_secret || ''
});

// Endpoint to fetch public key for frontend (Never exposes secret)
app.get('/api/razorpay-key', (req, res) => {
  if (!process.env.RAZORPAY_KEY_ID) {
    return res.status(500).json({ error: "Razorpay Key ID not configured on server" });
  }
  res.json({ key_id: process.env.RAZORPAY_KEY_ID });
});

// STEP 1: BACKEND - Create Order
// POST /api/create-order
// Request: { amount (in paise), currency, receipt }
// Return: { order_id, amount, currency }
app.post('/api/create-order', async (req, res) => {
  try {
    const { amount, currency = 'INR', receipt = `rcpt_${Date.now()}` } = req.body;

    // Validate amount >= 100 paise
    const parsedAmount = parseInt(amount, 10);
    if (!parsedAmount || isNaN(parsedAmount) || parsedAmount < 100) {
      return res.status(400).json({
        error: "Invalid amount. Minimum amount must be at least 100 paise (₹1.00)."
      });
    }

    if (!key_id || !key_secret) {
      return res.status(401).json({
        error: "Razorpay credentials missing on server."
      });
    }

    const options = {
      amount: parsedAmount,
      currency: currency || 'INR',
      receipt: receipt || `rcpt_${Date.now()}`,
      payment_capture: 1
    };

    const order = await razorpay.orders.create(options);
    if (!order || !order.id) {
      return res.status(500).json({ error: "Failed to create order with Razorpay" });
    }

    res.status(200).json({
      order_id: order.id,
      amount: order.amount,
      currency: order.currency
    });
  } catch (error) {
    console.error("Error creating Razorpay order:", error);
    // Handle auth failure or API error
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
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

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

    // Compare signatures
    const isAuthentic = (expectedSignature === razorpay_signature);

    if (isAuthentic) {
      return res.status(200).json({
        success: true,
        message: "Payment signature verified successfully",
        order_id: razorpay_order_id,
        payment_id: razorpay_payment_id
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

// Health check route
app.get('/health', (req, res) => {
  res.json({ status: "healthy", service: "CSMC Razorpay API", timestamp: new Date().toISOString() });
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
