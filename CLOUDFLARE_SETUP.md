# Cloudflare Email Routing Setup for pawclaw.top

## 🎯 Overview (100% FREE - No paid services!)

```
pawclaw.top (your domain)
    ↓
Cloudflare Email Routing (FREE)
    ↓
Cloudflare Worker (FREE)  ← Forwards emails
    ↓
Your Flask App (Render/Railway - FREE tier)
```

---

## 🔴 STEP 1: DNS Settings (YOU DO THIS NOW)

### 1.1 Add Domain to Cloudflare
1. Go to [dash.cloudflare.com](https://dash.cloudflare.com)
2. Click "Add Site"
3. Enter: `pawclaw.top`
4. Select **Free** plan
5. Cloudflare will give you **2 nameservers**

### 1.2 Update Nameservers at Your Registrar
Go to your domain registrar (where you bought pawclaw.top) and change nameservers to:
- Example: `lara.ns.cloudflare.com`
- Example: `greg.ns.cloudflare.com`

**(Cloudflare will show you the exact ones)**

⏳ **Wait 5-30 minutes for DNS to propagate**

---

## 🔴 STEP 2: Enable Email Routing (YOU DO THIS)

In Cloudflare dashboard:
1. Select `pawclaw.top`
2. Go to **Email** → **Email Routing**
3. Click "Enable Email Routing"
4. Add catch-all rule:
   - **Catch-all address**: `@pawclaw.top`
   - **Action**: Send to a Worker
   - **Worker**: (We'll create this in Step 4)

---

## 🔴 STEP 3: Deploy Flask App (YOU DO THIS)

### Option A: Render.com (Recommended)
1. Go to [render.com](https://render.com)
2. Sign up with GitHub
3. Click "New Web Service"
4. Connect your MailPi repo
5. Settings:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT`
   
6. **Environment Variables**:
   | Variable | Value | Where to Get |
   |----------|-------|--------------|
   | `UPSTASH_REDIS_URL` | `rediss://...` | Upstash.com (free) |
   | `UPSTASH_REDIS_TOKEN` | token | Upstash dashboard |
   | `API_KEY` | random string | Generate yourself |
   | `SUBDOMAIN` | `pawclaw.top` | (already set in code) |

7. Click "Create Web Service"
8. **Copy the URL** (e.g., `https://mailpi-xxxxx.onrender.com`)

### Option B: Railway.app
Similar process, also has free tier.

---

## 🔵 STEP 4: Deploy Cloudflare Worker (I'LL DO THIS)

Once you give me:
- Your Flask app URL from Step 3
- Your Cloudflare account access or API token

I'll deploy the worker that connects everything.

---

## 🔴 STEP 5: Update Frontend API Key (YOU DO THIS)

In `templates/index.html` line 137:
```javascript
apiKey: 'your_api_key_here', // Change from 'kiola645' to match your env variable
```

Then:
```bash
git add .
git commit -m "Update API key"
git push origin main
```

---

## 📋 CHECKLIST

| Task | Who | Status |
|------|-----|--------|
| Add pawclaw.top to Cloudflare | You | ⬜ |
| Update nameservers at registrar | You | ⬜ |
| Enable Email Routing in Cloudflare | You | ⬜ |
| Create Upstash Redis database | You | ⬜ |
| Deploy Flask app on Render | You | ⬜ |
| Copy Flask app URL | You | ⬜ |
| Deploy Cloudflare Worker | Me | ⬜ |
| Update API key in index.html | You | ⬜ |
| Test sending email | Both | ⬜ |

---

## 🚀 Quick Commands

### Redis Setup (Upstash)
1. Go to [upstash.com](https://upstash.com)
2. Sign up with Google
3. Create Redis database
4. Copy `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN`

### Generate API Key
```bash
# In terminal
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Or just make up a strong random string.

---

## ❓ Questions?

**Which step are you starting with?** Tell me and I'll guide you through it!

**Priority order:**
1. Add domain to Cloudflare (5 min)
2. Change nameservers (depends on registrar)
3. Create Upstash Redis (2 min)
4. Deploy on Render (5 min)
5. Then I deploy the Worker
