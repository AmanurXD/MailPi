// puter-worker.js - The Headless Browser Microservice Bridge

import puppeteer from 'puppeteer';
import express from 'express';

const PORT = 9001; // An internal port for the main server to talk to
let page; // We'll store the browser page globally in this worker

/**
 * Initializes a headless browser, navigates to a blank page,
 * and injects the Puter.js SDK.
 */
async function initializeBrowser() {
  console.log('[Puter Worker] Initializing headless browser...');
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'] // Important for server environments
  });
  
  page = await browser.newPage();
  
  // Create a minimal HTML environment to load the SDK
  await page.setContent(`
    <!DOCTYPE html>
    <html><head><title>Puter Worker</title></head><body>
      <script src="https://js.puter.com/v2/"></script>
    </body></html>
  `);

  // Log browser console messages to our worker's console for debugging
  page.on('console', msg => console.log(`[Browser Console] ${msg.text()}`));
  
  console.log('[Puter Worker] Browser initialized and Puter.js SDK is ready.');
}

/**
 * The core function that executes the Puter.ai.chat call inside the browser context.
 * @param {string} textBody - The email text to analyze.
 * @returns {Promise<object>} - A promise that resolves to the extracted data.
 */
async function callPuterAI(textBody) {
  if (!page) {
    throw new Error("Browser is not initialized.");
  }
  
  console.log('[Puter Worker] Executing Puter.ai.chat in browser context...');
  
  // page.evaluate executes code within the browser's JavaScript context
  const result = await page.evaluate(async (text) => {
    try {
      const completion = await window.puter.ai.chat(
        [
          {
            role: 'system',
            content: "You are an expert system that extracts security codes from emails. Analyze the user's text and use the `capture_email_codes` tool to return the codes you find. If a specific type of code is not found, return null for its value."
          },
          {
            role: 'user',
            content: text
          }
        ],
        {
          model: 'gpt-4o-mini',
          tools: [
            {
              type: "function",
              function: {
                name: "capture_email_codes",
                description: "Captures verification codes found in an email's text content.",
                parameters: {
                  type: "object",
                  properties: {
                    otp_digit: { type: "string", description: "The most likely numeric-only OTP or verification code (e.g., '123456')." },
                    otp_mix: { type: "string", description: "The most likely mixed alphanumeric code (e.g., 'AB12CD')." }
                  },
                  required: ["otp_digit", "otp_mix"]
                }
              }
            }
          ],
          tool_choice: { type: "function", function: { name: "capture_email_codes" } }
        }
      );

      const toolCall = completion.message.tool_calls?.[0];
      if (toolCall?.function.name === 'capture_email_codes') {
        const args = JSON.parse(toolCall.function.arguments);
        return {
          success: true,
          data: {
            otp_digit: args.otp_digit || null,
            otp_mix: args.otp_mix || null,
          }
        };
      }
      return { success: false, error: 'Tool call did not return expected function.' };
    } catch (error) {
      // Errors inside evaluate must be serialized to be sent back
      return { success: false, error: error.message };
    }
  }, textBody.slice(0, 2000)); // Pass textBody as an argument to evaluate

  if (result.success) {
    return result.data;
  } else {
    throw new Error(`Puter AI error in browser: ${result.error}`);
  }
}

// --- Main execution block ---
(async () => {
  await initializeBrowser();
  
  const app = express();
  app.use(express.json());

  // Expose a single endpoint for our main server to call
  app.post('/extract', async (req, res) => {
    const { textBody } = req.body;
    if (!textBody) {
      return res.status(400).json({ error: 'textBody is required' });
    }
    
    try {
      const data = await callPuterAI(textBody);
      res.json(data);
    } catch (error) {
      console.error('[Puter Worker] Extraction failed:', error.message);
      res.status(500).json({ error: 'Failed to process AI extraction.' });
    }
  });

  app.listen(PORT, () => {
    console.log(`[Puter Worker] Microservice listening on http://localhost:${PORT}`);
  });
})();
