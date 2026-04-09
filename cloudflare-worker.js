// Cloudflare Worker - Email Router for MailPi (Vercel + Upstash Version)
// This worker receives emails from Cloudflare Email Routing and stores directly in Upstash Redis

export default {
  async email(message, env, ctx) {
    // Upstash Redis REST API credentials
    const UPSTASH_REDIS_REST_URL = env.UPSTASH_REDIS_REST_URL;
    const UPSTASH_REDIS_REST_TOKEN = env.UPSTASH_REDIS_REST_TOKEN;
    
    // Your Vercel app webhook URL (optional - for processing notifications)
    const WEBHOOK_URL = env.WEBHOOK_URL || "https://mail-pi-ruby.vercel.app/webhook";
    
    try {
      const toAddress = message.to;
      const fromAddress = message.from;
      const subject = message.headers.get("subject") || "No Subject";
      
      // Get email content
      let textContent = "";
      let htmlContent = "";
      
      if (message.body) {
        try {
          textContent = await message.text();
        } catch (e) {
          console.log("Could not get text body:", e.message);
        }
      }

      // Create unique message ID
      const messageId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      const now = new Date().toISOString();
      
      // Prepare message data
      const messageData = {
        id: messageId,
        from: fromAddress,
        subject: subject,
        received_at: now,
        html_body: htmlContent || `<pre>${textContent}</pre>`,
        text_body: textContent,
        links: [],
        otp_digit: null,
        otp_mix: null
      };

      // Simple regex to extract OTPs
      const otpDigit = textContent.match(/\b\d{4,8}\b/g);
      const otpMix = textContent.match(/\b[a-zA-Z0-9]{6,10}\b/g);
      
      if (otpDigit) messageData.otp_digit = otpDigit[0];
      if (otpMix && otpMix[0] !== otpDigit?.[0]) messageData.otp_mix = otpMix[0];

      // Extract links
      const links = textContent.match(/https?:\/\/[^\s"'<>]+/g);
      if (links) messageData.links = [...new Set(links)];

      // Store in Upstash Redis via REST API
      const redisKey = `messages:${toAddress}`;
      
      // LPUSH - add to beginning of list
      const lpushResponse = await fetch(`${UPSTASH_REDIS_REST_URL}/lpush/${encodeURIComponent(redisKey)}`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify([JSON.stringify(messageData)])
      });

      if (!lpushResponse.ok) {
        const error = await lpushResponse.text();
        console.error(`Redis LPUSH failed: ${error}`);
        throw new Error(`Redis LPUSH failed: ${error}`);
      }

      // LTRIM - keep only last 100 messages
      await fetch(`${UPSTASH_REDIS_REST_URL}/ltrim/${encodeURIComponent(redisKey)}/0/99`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
        }
      });

      console.log(`Email stored in Redis: ${fromAddress} -> ${toAddress} (ID: ${messageId})`);

      // Optional: Notify Vercel app about new email
      if (WEBHOOK_URL) {
        try {
          await fetch(WEBHOOK_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              address: toAddress,
              message_id: messageId,
              from: fromAddress,
              subject: subject
            })
          });
        } catch (e) {
          console.log("Webhook notification failed (non-critical):", e.message);
        }
      }
      
    } catch (error) {
      console.error(`Error processing email: ${error.message}`);
      throw error;
    }
  }
};
