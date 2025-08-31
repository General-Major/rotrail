const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

const app = express();

// --- SECURITY ---
// Load service account credentials from environment variables.
// This is the secure way to handle your private key.
const serviceAccount = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  // Ensure escaped newlines in the private key are replaced.
  privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n')
};

// Initialize the Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// --- MIDDLEWARE ---
// Enable JSON body parsing for incoming requests.
app.use(express.json());

// Enable CORS for all routes to allow your Worker to call this service.
app.use(cors());

// --- SECURITY MIDDLEWARE ---
// This function checks for a secret key that only your Cloudflare Worker knows.
// This prevents the public from accessing your backend directly.
const checkAuth = (req, res, next) => {
  const secret = req.headers['x-secret-key'];
  if (secret !== process.env.WORKER_SECRET) {
    return res.status(403).json({ status: 'error', message: 'Forbidden' });
  }
  next();
};

// --- API ROUTE ---
// Define the endpoint that will fetch user data.
// We apply our security middleware here.
app.post('/getUserData', checkAuth, async (req, res) => {
  const { uid } = req.body;

  if (!uid) {
    return res.status(400).json({ status: 'error', message: 'User ID (uid) is required.' });
  }

  try {
    const userDoc = await db.collection('users').doc(uid).get();
    if (!userDoc.exists) {
      return res.status(404).json({ status: 'error', message: 'User data not found in Firestore.' });
    }

    const userData = userDoc.data();
    // Only send back the necessary data.
    res.status(200).json({
      status: 'success',
      subscriptionStatus: userData.subscriptionStatus || 'Free'
    });

  } catch (error) {
    console.error("Firestore Error:", error);
    res.status(500).json({ status: 'error', message: 'Internal Server Error' });
  }
});

// --- SERVER START ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
