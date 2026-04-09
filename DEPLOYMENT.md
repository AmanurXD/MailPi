# MailPi Deployment Guide for pawclaw.top

## ✅ Code Changes Complete
- Updated domain to `pawclaw.top` in `app.py`
- Updated branding in `templates/index.html`
- Changes committed to git

---

## 🔴 YOU MUST DO THESE STEPS

### 1. DNS Configuration (at your domain registrar)

You need to set up email handling for your domain. Choose ONE option:

#### Option A: Using Mailgun (Recommended)
1. Sign up at [mailgun.com](https://mailgun.com)
2. Add domain `pawclaw.top` in Mailgun dashboard
3. Add these DNS records at your registrar:
   
   | Type | Host | Value |
   |------|------|-------|
   | TXT | @ | v=spf1 include:mailgun.org ~all |
   | TXT | pic._domainkey | (Mailgun will give you this) |
   | MX | @ | mxa.mailgun.org (Priority: 10) |
   | MX | @ | mxb.mailgun.org (Priority: 10) |
   | CNAME | email.mailgun.org | mailgun.org |

4. In Mailgun, create a **Route**:
   - Match: catch_all()
   - Action: forward("https://mail.pawclaw.top/webhook")

#### Option B: Using ImprovMX (Free)
1. Sign up at [improvmx.com](https://improvmx.com)
2. Add domain `pawclaw.top`
3. Add these DNS records:
   
   | Type | Host | Value |
   |------|------|-------|
   | MX | @ | mx1.improvmx.com (Priority: 10) |
   | MX | @ | mx2.improvmx.com (Priority: 20) |
   | TXT | @ | v=spf1 include:spf.improvmx.com ~all |

4. Set up webhook forwarding (you may need a small forwarder script)

### 2. Deploy Application

Choose your platform:

#### Render.com (Easiest)
1. Go to [render.com](https://render.com)
2. Create new **Web Service**
3. Connect your GitHub repo
4. Set these **Environment Variables**:

   | Variable | Value | Get From |
   |----------|-------|----------|
   | `UPSTASH_REDIS_URL` | your_redis_url | [Upstash](https://upstash.com) |
   | `UPSTASH_REDIS_TOKEN` | your_token | Upstash dashboard |
   | `API_KEY` | strong_random_string | Generate yourself |
   | `OPENROUTER_API_KEY` | sk-or-... | [OpenRouter](https://openrouter.ai) (optional) |
   | `SUBDOMAIN` | pawclaw.top | (already set) |

5. Start service, get URL (e.g., `https://mail-pi.onrender.com`)

### 3. Point Domain to Your App

Add DNS record at your registrar:

| Type | Host | Value |
|------|------|-------|
| CNAME | mail | your-render-url.onrender.com |

Or if you want root domain:
| Type | Host | Value |
|------|------|-------|
| A | @ | (Your server's IP) |

### 4. Update Frontend API Key

In `templates/index.html` line 137:
```javascript
apiKey: 'kiola645', // <-- CHANGE THIS to match your API_KEY env var
```

Then commit and push:
```bash
git add .
git commit -m "Update API key"
git push origin main
```

---

## 🚀 Quick Start Services

### Upstash Redis (Required)
1. Go to [upstash.com](https://upstash.com)
2. Create Redis database
3. Copy the `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN`

### OpenRouter API (Optional - for AI OTP extraction)
1. Sign up at [openrouter.ai](https://openrouter.ai)
2. Create API key
3. Use free model: `meta-llama/llama-3.3-8b-instruct:free`

---

## 📝 Environment Variables Summary

| Variable | Required | Description |
|----------|----------|-------------|
| `UPSTASH_REDIS_URL` | ✅ Yes | Redis connection URL |
| `UPSTASH_REDIS_TOKEN` | ✅ Yes | Redis auth token |
| `API_KEY` | ✅ Yes | API authentication |
| `SUBDOMAIN` | ✅ Yes | pawclaw.top (set) |
| `OPENROUTER_API_KEY` | ❌ Optional | AI OTP extraction |

---

## 🔍 Testing

After deployment, test with:
```bash
curl -X POST https://mail.pawclaw.top/api/v1/addresses \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"alias": "test"}'
```

Then send an email to `test@pawclaw.top` and check if it appears!

---

## ❓ Need Help?

- Mailgun routes: [docs.mailgun.com](https://documentation.mailgun.com)
- Upstash Redis: [docs.upstash.com](https://docs.upstash.com/redis)
- Render deploy: [render.com/docs](https://render.com/docs)
