// Cloudflare Worker - Email Router for MailPi
// This worker receives emails from Cloudflare Email Routing and forwards to your Flask app

export default {
  async email(message, env, ctx) {
    // Your Flask app webhook URL (update this after you deploy)
    const WEBHOOK_URL = env.WEBHOOK_URL || "https://your-app-url.onrender.com/webhook";
    
    try {
      // Extract email data
      const to = message.headers.get("to") || message.to;
      const from = message.headers.get("from") || message.from;
      const subject = message.headers.get("subject") || "No Subject";
      
      // Get raw email content
      const rawEmail = await message.arrayBuffer();
      const rawBase64 = btoa(String.fromCharCode(...new Uint8Array(rawEmail)));
      
      // Get text content if available
      let textContent = "";
      let htmlContent = "";
      
      if (message.body) {
        // Try to get text body
        const textBody = await message.text();
        if (textBody) {
          textContent = textBody;
        }
      }

      // Prepare payload for Flask webhook
      const payload = {
        to: message.to,
        from: message.from,
        subject: subject,
        raw: rawBase64,  // Base64 encoded raw email
        text: textContent,
        html: htmlContent
      };

      // Forward to your Flask app
      const response = await fetch(WEBHOOK_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        console.error(`Webhook failed: ${response.status} ${await response.text()}`);
        // Still accept the email so Cloudflare doesn't retry
        return;
      }

      console.log(`Email forwarded successfully: ${message.from} -> ${message.to}`);
      
    } catch (error) {
      console.error(`Error processing email: ${error.message}`);
      // Return error to Cloudflare so it knows something went wrong
      throw error;
    }
  }
};
