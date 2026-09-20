# CSMC DP Spatial Portal - Payment Backend API

Backend service providing Razorpay Order Creation and HMAC-SHA256 Payment Signature Verification for the CSMC DP Spatial Portal.

## Endpoints

- `POST /api/create-order` - Creates Razorpay order (amount in paise, min 100).
- `POST /api/verify-payment` - Verifies HMAC-SHA256 signature using `RAZORPAY_KEY_SECRET`.
- `GET /api/razorpay-key` - Returns public Key ID for the frontend.
- `GET /health` - Health check endpoint.

## Deployment on Render.com (Free)

1. Go to [https://dashboard.render.com](https://dashboard.render.com)
2. Click **New +** -> **Web Service**
3. Connect this repository (`shivaiitb21/csmc-dp-backend`)
4. Settings:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
5. Under **Environment Variables**, add:
   - `RAZORPAY_KEY_ID`: `<YOUR_RAZORPAY_KEY_ID>`
   - `RAZORPAY_KEY_SECRET`: `<YOUR_RAZORPAY_KEY_SECRET>`
6. Click **Deploy Web Service**
7. Once deployed, copy your Render URL (e.g., `https://csmc-dp-backend.onrender.com`).
