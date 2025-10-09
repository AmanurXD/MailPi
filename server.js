// server.js - The Main Application (Updated to use the Worker Bridge)

// --- 1. Imports and Setup ---
import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import Redis from 'ioredis';
import { simpleParser } from 'mailparser';
import { customAlphabet } from 'nanoid';
import { spawn } from 'child_process'; // To run our worker

// --- 2. Configuration & Initialization ---
const PORT = process.env.PORT || 3000;
const PUTER_WORKER_PORT = 9001; // Must match the worker's port
// ... (All other configurations like SUBDOMAIN, API_KEY, Redis, etc., are identical)
const SUBDOMAIN = process.env.SUBDOMAIN || 'example.com';
const API_KEY = process.env.API_KEY;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const redis = new Redis(process.env.REDIS_URL, {
  tls: { rejectUnauthorized: false },
  lazyConnect: true,
});
redis.on('connect', () => console.log('[INFO] Successfully connected to Redis.'));
redis.on('error', (err) => console.error('[ERROR] Redis connection error:', err));
await redis.connect();

const ADDRESSES_KEY = 'addresses';
const MESSAGES_PREFIX = 'messages:';


// --- 3. Start the Puter Worker as a Child Process ---
console.log('[Main Server] Spawning Puter Worker process...');
const workerProcess = spawn('node', ['puter-worker.js'], { stdio: 'inherit' });
workerProcess.on('error', (err) => {
  console.error('[FATAL] Failed to start Puter Worker process:', err);
  process.exit(1);
});


// --- 4. Middleware (UNCHANGED) ---
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public')); 
const requireApiKey = (req, res, next) => {
  if (!API_KEY) return res.status(500).json({ error: 'API service is not configured.' });
  const providedKey = req.headers['x-api-key'];
  if (!providedKey || providedKey !== API_KEY) return res.status(401).json({ error: 'Unauthorized. Invalid or missing API Key.' });
  next();
};

// --- 5. Helper Functions (UPDATED FOR WORKER) ---

// THIS IS THE ONLY FUNCTION WHOSE *INSIDES* HAVE CHANGED
async function extractDetailsWithAI(textBody) {
  try {
    const response = await fetch(`http://localhost:${PUTER_WORKER_PORT}/extract`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ textBody }),
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `Worker responded with status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('[AI_ERROR] Could not communicate with Puter Worker:', error.message);
    return { otp_digit: null, otp_mix: null }; // Fail gracefully
  }
}

// THIS FUNCTION IS IDENTICAL AND PRESERVED
function extractDetailsWithRegex(htmlBody, textBody) {
  const content = `${htmlBody} ${textBody}`;
  const links = [...new Set(content.match(/https?:\/\/[^\s"\'<>]+/g) || [])];
  const otp_lists = content.match(/\b(\d{4,8})\b/g) || [];
  return { links, otp_lists };
}

// THIS FUNCTION IS IDENTICAL AND PRESERVED
async function storeMessage(to, from, subject, rawEmail) {
  const toAddress = to;
  const addressExists = await redis.hexists(ADDRESSES_KEY, toAddress);
  if (!addressExists) {
    console.log(`[Webhook] Mail for unknown/expired address: ${toAddress}`);
    return;
  }

  let parsed;
  try {
    parsed = await simpleParser(rawEmail);
  } catch (e) {
    console.error('[ERROR] Mail parsing failed:', e);
    parsed = { html: '<h1>Error parsing email content!</h1>', text: 'Failed to parse.', from: { text: from }};
  }
  
  const textBody = parsed.text || "No plain text content found.";
  let htmlBody = parsed.html || "No HTML content found.";
  if (htmlBody === "No HTML content found." && textBody) {
    htmlBody = `<pre>${textBody}</pre>`;
  }

  const [aiData, regexData] = await Promise.all([
    extractDetailsWithAI(textBody),
    extractDetailsWithRegex(htmlBody, textBody)
  ]);
  const extractedData = { ...aiData, ...regexData };

  const messageId = `${Date.now()}-${customAlphabet('1234567890abcdef', 6)()}`;
  const messageData = {
    id: messageId,
    from: parsed.from?.text || from,
    subject: parsed.subject || subject,
    received_at: new Date().toISOString(),
    html_body: htmlBody,
    text_body: textBody,
    ...extractedData
  };

  await redis.lpush(`${MESSAGES_PREFIX}${toAddress}`, JSON.stringify(messageData));
  await redis.ltrim(`${MESSAGES_PREFIX}${toAddress}`, 0, 99);

  const miniMsg = {
    id: messageId,
    address: toAddress,
    from: messageData.from,
    subject: messageData.subject,
    received_at: messageData.received_at,
    otp_digit: extractedData.otp_digit,
    otp_mix: extractedData.otp_mix
  };
  io.to(toAddress).emit('new_mail', miniMsg);
  console.log(`[INFO] Stored and emitted message for ${toAddress}`);
}

// --- 6. API Endpoints (UNCHANGED AND PRESERVED) ---
// All your API routes (/api/v1/addresses, etc.) are exactly the same as before.
// I'm omitting them here for brevity, but you should copy them from the previous answer.
// Just paste the entire `apiRouter` block here.
const apiRouter = express.Router();
apiRouter.post('/addresses', requireApiKey, /* ... */);
apiRouter.get('/addresses/:email/messages', requireApiKey, /* ... */);
apiRouter.get('/messages/:email/:messageId', requireApiKey, /* ... */);
app.use('/api/v1', apiRouter);


// --- 7. Frontend & Webhook Routes (UNCHANGED AND PRESERVED) ---
app.post('/webhook', async (req, res) => { /* ... */ });
app.get('/addresses', async (req, res) => { /* ... */ });


// --- 8. Socket.IO and Server Start (UNCHANGED AND PRESERVED) ---
io.on('connection', (socket) => { /* ... */ });

server.listen(PORT, () => {
  console.log(`🚀 Main Server is listening on http://localhost:${PORT}`);
});
