# MailPi

MailPi is a mailbox API and web inbox app built with Flask, Flask-SocketIO, and Upstash Redis.

## How it works

This project is not a full SMTP server. It depends on an inbound mail service to receive email for your domain and send a JSON webhook to this app.

The flow is:

1. The UI or API creates an address like `alias@pawclaw.top`.
2. The address metadata is stored in Upstash Redis.
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

If your provider sends `text` instead of `raw`, this app accepts that as a fallback.

## What this API can do

- Create permanent mailboxes by default
- Create expiring mailboxes if you explicitly want TTL-based addresses
- List mailboxes
- Inspect a mailbox
- List message summaries
- Read full messages
- Delete one message
- Purge all messages for a mailbox
- Delete a mailbox and its messages
- Extract OTPs and links from incoming emails

## Services you need

- A Python host for this Flask app
- An Upstash Redis database
- A domain: `pawclaw.top`
- An inbound mail routing provider that can forward inbound mail to an HTTP webhook

Cloudflare Email Routing plus a Worker is one practical option for this setup.

## Environment variables

Copy `.env.example` into your deployment platform and set:

- `UPSTASH_REDIS_URL`
- `UPSTASH_REDIS_TOKEN`
- `SUBDOMAIN=pawclaw.top`
- `APP_PUBLIC_URL=https://mailpi-y86z.onrender.com`
- `API_KEY`
- `OPENROUTER_API_KEY` if you want AI OTP extraction
- `SITE_TITLE`
- `WEBHOOK_SECRET`
- `ADDRESS_TTL_DAYS` if you want expiring addresses by default
- `MAX_MESSAGES_PER_ADDRESS`

`OPENROUTER_API_KEY` is optional. Without it, inboxes still work and the app simply skips AI code extraction.

If `ADDRESS_TTL_DAYS` is not set, mailboxes are permanent by default.

## Install and run

```bash
pip install -r requirements.txt
gunicorn --worker-class eventlet -w 1 app:app
```

This repo includes `.python-version` pinned to `3.11.11`.

For local development:

```bash
python app.py
```

## API overview

All API routes are under `/api/v1` and require:

```http
X-API-Key: <your-api-key>
Content-Type: application/json
```

### Create or load an address

```http
POST /api/v1/addresses
```

Example body:

```json
{
  "alias": "myalias",
  "never_expires": true,
  "tags": ["signup", "test"],
  "notes": "Primary API inbox"
}
```

Optional fields:

- `alias`
- `never_expires`
- `expires_in_days`
- `tags`
- `notes`

### List all addresses

```http
GET /api/v1/addresses
```

Optional query params:

- `include_expired=true`

### Get one address

```http
GET /api/v1/addresses/<email>
```

### Delete one address

Deletes the mailbox and all stored messages.

```http
DELETE /api/v1/addresses/<email>
```

### List messages for an address

```http
GET /api/v1/addresses/<email>/messages?limit=50&offset=0
```

### Get one full message

```http
GET /api/v1/addresses/<email>/messages/<message_id>
```

### Delete one message

```http
DELETE /api/v1/addresses/<email>/messages/<message_id>
```

### Delete all messages for an address

```http
DELETE /api/v1/addresses/<email>/messages
```

### Get service metadata

```http
GET /api/v1/service
```

### Webhook endpoint

Inbound providers should send mail to:

```http
POST /webhook
```

With header:

```http
X-Webhook-Secret: <your-webhook-secret>
```

And JSON body:

```json
{
  "to": "alias@pawclaw.top",
  "from": "sender@example.com",
  "subject": "Hello",
  "raw": "full raw RFC822 message"
}
```

### Example create-address response

```json
{
  "address": "myalias@pawclaw.top",
  "alias": "myalias",
  "created_at": "2026-04-20T00:00:00.000000",
  "updated_at": "2026-04-20T00:00:00.000000",
  "expires_at": null,
  "never_expires": true,
  "status": "active",
  "message_count": 0,
  "tags": ["signup", "test"],
  "notes": "Primary API inbox"
}
```

### Example message response

```json
{
  "id": "1713570000.1234-abcd",
  "from": "Example <hello@example.com>",
  "to": "myalias@pawclaw.top",
  "subject": "Verification code",
  "received_at": "2026-04-20T00:00:15.000000",
  "provider_message_id": "<message-id@example.com>",
  "html_body": "<html>...</html>",
  "text_body": "Your code is 123456",
  "links": ["https://example.com/verify"],
  "attachments": [],
  "otp_digit": "123456",
  "otp_mix": null
}
```

## Hosting notes

You need two separate pieces:

1. Web hosting for the app
2. Mail routing for inbound email on `pawclaw.top`

Typical setup:

- Host the app on Render
- Use Upstash Redis for storage
- Put `pawclaw.top` on Cloudflare DNS
- Enable Cloudflare Email Routing
- Route inbound mail to the Worker
- Have the Worker call `POST /webhook`

## Cloudflare Worker setup

- Worker source: `cloudflare-worker/src/index.js`
- Root Wrangler config for git deploys: `wrangler.jsonc`
- Worker variables:
  - `MAILPI_WEBHOOK_URL=https://mailpi-y86z.onrender.com/webhook`
  - `MAILPI_WEBHOOK_SECRET=<same value as WEBHOOK_SECRET on Render>`
  - `FORWARD_TO=` optional

## Important notes

- The frontend still uses the API key from the rendered page, so this is suitable for a personal tool, not a hardened public service
- Mailboxes are permanent by default unless you configure `ADDRESS_TTL_DAYS` or pass `expires_in_days`
- Redis is required at startup; the app exits if it cannot connect
- The app only stores mail for addresses already known to Redis
- Messages are capped by `MAX_MESSAGES_PER_ADDRESS`
- If `WEBHOOK_SECRET` is set, `/webhook` only accepts posts that include the matching `X-Webhook-Secret` header
