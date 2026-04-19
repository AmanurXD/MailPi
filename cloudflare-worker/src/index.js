async function readRawEmail(message) {
  const reader = message.raw.getReader();
  const chunks = [];

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(totalLength);
  let offset = 0;

  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  return new TextDecoder().decode(merged);
}

export default {
  async email(message, env) {
    const raw = await readRawEmail(message);
    const subject = message.headers.get("subject") || "";
    const webhookUrl = env.MAILPI_WEBHOOK_URL;
    const hasWebhookSecret = Boolean(env.MAILPI_WEBHOOK_SECRET);

    console.log(
      JSON.stringify({
        event: "incoming_email",
        to: message.to,
        from: message.from,
        subject,
        rawSize: message.rawSize,
        webhookConfigured: Boolean(webhookUrl),
        webhookSecretConfigured: hasWebhookSecret,
      }),
    );

    if (!webhookUrl) {
      console.error("MAILPI_WEBHOOK_URL is not configured");
      message.setReject("MailPi webhook URL is not configured");
      return;
    }

    try {
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Webhook-Secret": env.MAILPI_WEBHOOK_SECRET,
        },
        body: JSON.stringify({
          to: message.to,
          from: message.from,
          subject,
          raw,
          raw_size: message.rawSize,
        }),
      });

      const detail = await response.text();
      console.log(
        JSON.stringify({
          event: "mailpi_webhook_response",
          status: response.status,
          ok: response.ok,
          detail: detail.slice(0, 200),
        }),
      );

      if (!response.ok) {
        message.setReject(`MailPi webhook failed: ${response.status} ${detail.slice(0, 120)}`);
        return;
      }
    } catch (error) {
      console.error(`MailPi webhook fetch failed: ${error.message}`);
      message.setReject(`MailPi webhook fetch failed: ${error.message.slice(0, 120)}`);
      return;
    }

    if (env.FORWARD_TO && message.canBeForwarded) {
      await message.forward(env.FORWARD_TO);
    }
  },
};
