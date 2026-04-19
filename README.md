# MailPi

MailPi is a small disposable mailbox app built with Flask, Flask-SocketIO, and Upstash Redis.

## How the old version worked

This project was not a full SMTP server. It depended on an external inbound mail service to receive email for your domain and send a JSON webhook to this app.

The app flow is:

1. The UI creates a disposable address like `alias@pawclaw.top`.
2. The address is stored in Upstash Redis.
3. Your mail-routing provider receives mail for `pawclaw.top`.
4. That provider posts the email payload to `POST /webhook`.
5. MailPi parses the message, stores it in Redis, and pushes a live inbox update over Socket.IO.

The webhook payload expected by MailPi looks like:

```json
{
  "to": "alias@pawclaw.top",
  "from": "sender@example.com",
  "subject": "Hello",
  "raw": "full raw RFC822 message"
}
```

If your provider sends `text` instead of `raw`, this app already accepts that as a fallback.

## Services you need again

- A Python host for this Flask app
- An Upstash Redis database
- A domain: `pawclaw.top`
- An inbound mail routing provider that can forward inbound mail to an HTTP webhook

Cloudflare Email Routing plus a small Worker is one practical option if you want to recreate the same pattern. Any provider is fine as long as it can transform inbound mail into the JSON fields above and call your `/webhook` endpoint.

## Environment variables

Copy `.env.example` into your deployment platform and set:

- `UPSTASH_REDIS_URL`
- `UPSTASH_REDIS_TOKEN`
- `SUBDOMAIN=pawclaw.top`
- `APP_PUBLIC_URL=https://pawclaw.top`
- `API_KEY`
- `OPENROUTER_API_KEY` if you want AI OTP extraction
- `SITE_TITLE`
- `WEBHOOK_SECRET`

`OPENROUTER_API_KEY` is optional. Without it, inboxes still work and the app simply skips AI code extraction.

## Install and run

```bash
pip install -r requirements.txt
gunicorn --worker-class eventlet -w 1 app:app
```

This repo includes `.python-version` pinned to `3.11.11` so Render does not default to a newer Python runtime than this older stack was built around.

For local development you can also run:

```bash
python app.py
```

but production should use Gunicorn.

## DNS and hosting notes for pawclaw.top

You need two separate pieces:

1. Web hosting for the app at `pawclaw.top`
2. Mail routing for inbound email on `pawclaw.top`

Typical setup:

- Point `pawclaw.top` to your app host
- Configure MX records to your inbound mail-routing provider
- Add any SPF/DKIM records your provider requires
- Configure that provider to send inbound mail to `https://pawclaw.top/webhook`

## Recreate the old flow with Render + Upstash + Cloudflare

### 1. Render

- Push this repo to GitHub.
- Create a Render Web Service from the repo, or use the included `render.yaml`.
- Render's Flask docs show the standard Python setup shape: build with `pip install -r requirements.txt` and start with Gunicorn. This app uses `gunicorn --worker-class eventlet -w 1 app:app` because it relies on Flask-SocketIO.
- Add the custom domain `pawclaw.top` in Render.
- Set all variables from `.env.example`.

### 2. Upstash

- Create a Redis database in Upstash.
- Use the database endpoint/password in `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN`.
- Upstash documents that TLS is enabled by default, which matches this app's `rediss://` connection style.

### 3. Cloudflare DNS + Email Routing

- Put `pawclaw.top` on Cloudflare DNS.
- In Cloudflare, enable Email Routing for the domain and let Cloudflare add the required DNS records.
- Turn on Catch-all so any generated alias at `@pawclaw.top` reaches the Worker.
- Create an Email Worker destination, not a normal mailbox forward.

### 4. Cloudflare Worker

- The Worker source is in `cloudflare-worker/src/index.js`.
- This repo now includes a root `wrangler.jsonc` so Cloudflare Git deploys can detect the Worker entry point automatically.
- If you prefer deploying from the subfolder manually, use `cloudflare-worker/wrangler.jsonc.example` as the template.
- Add Worker secrets:
  - `MAILPI_WEBHOOK_URL=https://pawclaw.top/webhook`
  - `MAILPI_WEBHOOK_SECRET=<same value as WEBHOOK_SECRET on Render>`
- Optional:
  - `FORWARD_TO=<your real mailbox>` if you also want a personal copy of every message.

### 5. Bind the Worker to inbound mail

- In Cloudflare Email Routing, create a rule with Action = `Send to a Worker`.
- Use either:
  - Catch-all for `*@pawclaw.top`
  - Or specific aliases if you only want named inboxes

Catch-all is the closest match to how this disposable system used to feel. The app itself still decides whether a mailbox is valid by checking whether it was generated and stored in Redis.

### 6. First test

1. Open `https://pawclaw.top`.
2. Generate an address.
3. Send a test email to that address.
4. Confirm the Worker delivered it and the inbox updates.
5. If the inbox stays empty, check:
   - Render logs for `/webhook`
   - Cloudflare Worker logs
   - Cloudflare Email Routing rule status
   - Upstash connectivity

## Files added for the hosted setup

- `render.yaml` for Render service bootstrap
- `wrangler.jsonc` for Cloudflare Worker git deploys from the repo root
- `cloudflare-worker/src/index.js` for inbound email delivery to MailPi
- `cloudflare-worker/wrangler.jsonc.example` for Worker deployment
- `cloudflare-worker/.dev.vars.example` for local Worker testing

## Important caveats from the recovered commit

- The frontend still uses the API key from the rendered page, so this is suitable for a personal tool, not a hardened public service
- Address expiry timestamps are stored, but automatic cleanup is not implemented
- Redis is required at startup; the app exits if it cannot connect
- The app only stores mail for generated addresses already known to Redis
- If `WEBHOOK_SECRET` is set, `/webhook` only accepts posts that include the matching `X-Webhook-Secret` header
