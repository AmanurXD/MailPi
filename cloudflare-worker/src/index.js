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

    const response = await fetch(env.MAILPI_WEBHOOK_URL, {
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

    if (!response.ok) {
      const detail = await response.text();
      message.setReject(`MailPi webhook failed: ${response.status} ${detail.slice(0, 120)}`);
      return;
    }

    if (env.FORWARD_TO && message.canBeForwarded) {
      await message.forward(env.FORWARD_TO);
    }
  },
};
