// server.js - The Complete and Final Main Application

// --- 1. Imports and Setup ---
import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import Redis from 'ioredis';
import { simpleParser } from 'mailparser';
import { customAlphabet } from 'nanoid';
import { spawn } from 'child_process'; // To run our worker as a background process

// --- 2. Configuration & Initialization ---
const PORT = process.env.PORT || 3000;
const PUTER_WORKER_PORT = 9001; // The internal port for our browser microservice
const SUBDOMAIN = process.env.SUBDOMAIN || 'example.com';
const API_KEY = process.env.API_KEY;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const redis = new Redis(process.env.REDIS_URL, {
  tls: { rejectUnauthorized: false }, // Common requirement for cloud Redis providers
  lazyConnect: true,
});
redis.on('connect', () => console.log('[Main Server] Successfully connected to Redis.'));
redis.on('error', (err) => console.error('[Main Server] Redis connection error:', err));
await redis.connect();

const ADDRESSES_KEY = 'addresses';
const MESSAGES_PREFIX = 'messages:';

// --- 3. Start the Puter Worker ---
console.log('[Main Server] Spawning Puter Worker process...');
// 'inherit' pipes the worker's console output to this process's console, which is great for debugging
const workerProcess = spawn('node', ['puter-worker.js'], { stdio: 'inherit' });
workerProcess.on('error', (err) => {
  console.error('[FATAL] Failed to start Puter Worker process. Please check if Node.js and Puppeteer are installed correctly.', err);
  process.exit(1);
});

// --- 4. Middleware ---
app.use(express.json({ limit: '10mb' })); // For parsing JSON bodies from webhooks/API calls
app.use(express.static('public')); // Serves your index.html from the 'public' folder

const requireApiKey = (req, res, next) => {
  if (!API_KEY) {
    return res.status(500).json({ error: 'API service is not configured on the server.' });
  }
  const providedKey = req.headers['x-api-key'];
  if (!providedKey || providedKey !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized. Invalid or missing API Key.' });
  }
  next();
};

// --- 5. Helper Functions ---
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
    console.error('[Main Server] Could not communicate with Puter Worker:', error.message);
    return { otp_digit: null, otp_mix: null }; // Fail gracefully, don't crash the app
  }
}

function extractDetailsWithRegex(htmlBody, textBody) {
  const content = `${htmlBody} ${textBody}`;
  const links = [...new Set(content.match(/https?:\/\/[^\s"\'<>]+/g) || [])];
  const otp_lists = content.match(/\b(\d{4,8})\b/g) || [];
  return { links, otp_lists };
}

async function storeMessage(to, from, subject, rawEmail) {
  const toAddress = to;
  if (!await redis.hexists(ADDRESSES_KEY, toAddress)) {
    console.log(`[Webhook] Mail for unknown/expired address: ${toAddress}. Ignoring.`);
    return;
  }

  let parsed = {};
  try {
    parsed = await simpleParser(rawEmail);
  } catch (e) {
    console.error('[ERROR] Mail parsing failed:', e);
    parsed = { html: '<h1>Error: Failed to parse email content.</h1>', text: 'Could not parse.', from: { text: from } };
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
  console.log(`[Main Server] Stored and emitted real-time update for message to ${toAddress}`);
}

// --- 6. API Endpoints ---
const apiRouter = express.Router();

apiRouter.post('/addresses', requireApiKey, async (req, res) => {
  const { alias } = req.body || {};
  const aliasPart = alias || customAlphabet('abcdefghijklmnopqrstuvwxyz0123456789', 6)();
  const address = `${aliasPart}@${SUBDOMAIN}`;
  const expires = new Date();
  expires.setDate(expires.getDate() + 14);
  await redis.hset(ADDRESSES_KEY, address, expires.toISOString());
  res.status(201).json({ address, expires_at: expires.toISOString() });
});

apiRouter.get('/addresses/:email/messages', requireApiKey, async (req, res) => {
  const { email } = req.params;
  const messagesJson = await redis.lrange(`${MESSAGES_PREFIX}${email}`, 0, -1);
  const messages = messagesJson.map(JSON.parse).map(msg => ({
    id: msg.id,
    from: msg.from,
    subject: msg.subject,
    received_at: msg.received_at,
    otp_digit: msg.otp_digit,
    otp_mix: msg.otp_mix,
    has_links: (msg.links || []).length > 0,
  }));
  res.json(messages);
});

apiRouter.get('/messages/:email/:messageId', requireApiKey, async (req, res) => {
    const { email, messageId } = req.params;
    const messagesJson = await redis.lrange(`${MESSAGES_PREFIX}${email}`, 0, -1);
    const message = messagesJson.map(JSON.parse).find(msg => msg.id === messageId);
    if (message) res.json(message);
    else res.status(404).json({ error: 'Message not found.' });
});

app.use('/api/v1', apiRouter);

// --- 7. Frontend & Webhook Routes ---
app.post('/webhook', async (req, res) => {
  const { to, from, subject, raw } = req.body;
  if (!to) return res.status(400).json({ error: "Missing 'to' field" });
  res.status(202).json({ status: "accepted" }); // Respond immediately
  storeMessage(to, from, subject, raw); // Process in background
});

app.get('/addresses', async (req, res) => {
    const allAddresses = await redis.hgetall(ADDRESSES_KEY);
    const addressList = Object.entries(allAddresses).map(([address, expires_at]) => ({
        address, expires_at,
    })).sort((a, b) => new Date(b.expires_at) - new Date(a.expires_at));
    res.json(addressList);
});

// --- 8. Socket.IO and Server Start ---
io.on('connection', (socket) => {
  console.log(`[Socket] Client connected: ${socket.id}`);
  socket.on('join_mailbox', (data) => {
    if (data.address) {
      socket.join(data.address);
      console.log(`[Socket] Client ${socket.id} joined room: ${data.address}`);
    }
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Main Server is listening on http://localhost:${PORT}`);
});
