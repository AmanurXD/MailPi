// puter-worker.js - The Complete and Final Browser Microservice Bridge

import puppeteer from 'puppeteer';
import express from 'express';

const PORT = 9001; // An internal port for the main server to talk to
let page; // This will hold the persistent browser page instance

/**
 * Initializes a single, persistent headless browser instance.
 * It navigates to a blank page and injects the Puter.js SDK.
 * This is much faster than launching a new browser for every request.
 */
async function initializeBrowser() {
  console.log('[Puter Worker] Initializing headless browser...');
  const browser = await puppeteer.launch({
    headless: true,
    // These arguments are crucial for running in server/Docker environments
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  page = await browser.newPage();
  
  // Create a minimal HTML environment just to load the script
  await page.setContent('<!DOCTYPE html><html><head><title>Puter Worker</title></head><body><script src="https://js.puter.com/v2/"></script></body></html>');

  // This is useful for debugging: it pipes the browser's console logs to our Node.js console
  page.on('console', msg => console.log(`[Browser Console] ${msg.text()}`));
  
  console.log('[Puter Worker] Browser initialized and Puter.js SDK is ready to receive requests.');
}

/**
 * This function is the bridge. It executes the Puter.ai.chat call 
 * inside the browser's context where the SDK is loaded.
 * @param {string} textBody - The email text to analyze.
 * @returns {Promise<object>} - A promise that resolves to the extracted data.
 */
async function callPuterAI(textBody) {
  if (!page) {
    throw new Error("Browser has not been initialized. The worker may be starting up.");
  }
  
  console.log('[Puter Worker] Executing Puter.ai.chat in browser context...');
  
  // page.evaluate runs the provided function within the browser's JavaScript context.
  // We pass `textBody` as an argument to avoid string injection issues.
  const result = await page.evaluate(async (text) => {
    try {
      // Inside this function, `window.puter` exists because we loaded the SDK.
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
          model: 'gpt-4o-mini', // A fast, capable, and cost-effective model
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
      return { success: false, error: 'AI did not use the required function tool.' };
    } catch (error) {
      // Errors inside `evaluate` must be serializable to be sent back to Node.js
      return { success: false, error: error.message };
    }
  }, textBody.slice(0, 2000)); // We pass the textBody as an argument here

  if (result.success) {
    return result.data;
  } else {
    throw new Error(`Puter AI error inside browser: ${result.error}`);
  }
}

// --- Main execution block for the worker ---
(async () => {
  await initializeBrowser();
  
  const app = express();
  app.use(express.json());

  // We expose a single, simple endpoint for our main server to call.
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
    console.log(`[Puter Worker] Microservice is ready and listening on http://localhost:${PORT}`);
  });
})();
