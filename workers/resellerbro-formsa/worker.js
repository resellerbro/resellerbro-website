
const ALLOWED_ORIGINS = new Set([
  "https://resellerbro.com",
  "https://www.resellerbro.com"
]);

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers
    }
  });

const clean = (value, max = 500) =>
  typeof value === "string" ? value.trim().slice(0, max) : "";

const validEmail = (value) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) &&
  value.length <= 128;

async function verifyTurnstile(request, env, token) {
  if (!env.TURNSTILE_SECRET_KEY || !token) {
    console.log("Turnstile diagnostic", {
      error: "Missing secret or token",
      missingSecret: !env.TURNSTILE_SECRET_KEY,
      missingToken: !token
    });
    return false;
  }

  const body = new URLSearchParams({
    secret: env.TURNSTILE_SECRET_KEY,
    response: token
  });

  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) body.set("remoteip", ip);

  const response = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    { method: "POST", body }
  );

  if (!response.ok) {
    throw new Error("Turnstile service error");
  }

  const result = await response.json();

  // Logs verification results, never secrets or tokens.
  console.log("Turnstile diagnostic", {
    success: result.success === true,
    hostname: result.hostname || null,
    errors: result["error-codes"] || [],
    expectedHostname: "resellerbro.com"
  });

  return (
    result.success === true &&
    result.hostname === "resellerbro.com"
  );
}

// Send notification to Reseller Bro email.
async function sendSignupNotification(env, data) {
  if (!env.RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY missing");
  }

  const form = clean(data.form, 30);
  const subjects = {
    waitlist: "New Reseller Bro Waitlist Signup",
    beta: "New Reseller Bro Beta Signup",
    partner: "New Reseller Bro Partner Application",
    founder: "New Reseller Bro Founder Message"
  };

  const subject = subjects[form];
  if (!subject) return;

  const details = [
    `Form: ${form}`,
    `Name: ${clean(data.name, 256) || "Not provided"}`,
    `Email: ${clean(data.email, 128) || "Not provided"}`,
    `Handle: ${clean(data.primary_handle, 256) || "Not provided"}`,
    `Channel: ${clean(data.core_channel, 100) || "Not provided"}`,
    `Audience: ${clean(String(data.audience_size ?? ""), 100) || "Not provided"}`,
    `Category: ${clean(data.resale_category, 100) || "Not provided"}`,    `Message: ${
      clean(data.message || data.application_message, 2000) ||
      "Not provided"
    }`
  ].join("\n");

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "Reseller Bro <notifications@resellerbro.com>",
        to: ["joe@resellerbro.com"],
        ...(form === "partner" && validEmail(clean(data.email, 128).toLowerCase())
          ? { reply_to: clean(data.email, 128).toLowerCase() }
          : {}),
        subject,
        text: details
      })
    }
  );

  if (!response.ok) {
    throw new Error(
      `Resend notification failed: ${response.status}`
    );
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");

    const cors =
      origin && ALLOWED_ORIGINS.has(origin)
        ? {
            "Access-Control-Allow-Origin": origin,
            Vary: "Origin"
          }
        : {};

    // Health check
    if (request.method === "GET") {
      return json({
        service: "Reseller Bro Forms",
        status: "ready"
      });
    }

    // CORS preflight
    if (request.method === "OPTIONS") {
      if (!origin || !ALLOWED_ORIGINS.has(origin)) {
        return json({ error: "Forbidden" }, 403);
      }

      return new Response(null, {
        status: 204,
        headers: {
          ...cors,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "600"
        }
      });
    }

    if (request.method !== "POST") {
      return json({ error: "Method not allowed" }, 405, cors);
    }

    if (!origin || !ALLOWED_ORIGINS.has(origin)) {
      return json({ error: "Forbidden" }, 403, cors);
    }

    if (!env.DB) {
      return json({ error: "Database unavailable" }, 503, cors);
    }

    if (!env.TURNSTILE_SECRET_KEY) {
      return json(
        { error: "Verification unavailable" },
        503,
        cors
      );
    }

    const contentType =
      request.headers.get("Content-Type") || "";

    if (
      !contentType.toLowerCase().startsWith("application/json")
    ) {
      return json({ error: "JSON required" }, 415, cors);
    }

    const size = Number(
      request.headers.get("Content-Length") || 0
    );

    if (size > 10000) {
      return json({ error: "Request too large" }, 413, cors);
    }

    let data;

    try {
      const body = await request.text();

      if (body.length > 10000) {
        return json(
          { error: "Request too large" },
          413,
          cors
        );
      }

      data = JSON.parse(body);

      if (
        !data ||
        typeof data !== "object" ||
        Array.isArray(data)
      ) {
        throw new Error("Invalid input");
      }
    } catch {
      return json({ error: "Invalid JSON" }, 400, cors);
    }

    // Honeypot protection
    if (data.website) {
      return json({ success: true }, 200, cors);
    }

    // Verify Cloudflare Turnstile
    const token = clean(data.turnstileToken, 2048);

    if (!token) {
      return json(
        { error: "Complete security verification" },
        400,
        cors
      );
    }

    try {
      const verified = await verifyTurnstile(
        request,
        env,
        token
      );

      if (!verified) {
        return json(
          { error: "Security verification failed" },
          403,
          cors
        );
      }
    } catch (error) {
      console.error(
        "Turnstile verification unavailable:",
        error.name
      );

      return json(
        { error: "Verification temporarily unavailable" },
        503,
        cors
      );
    }

    // Process verified submission
    try {
      const form = clean(data.form, 30);
      const email = clean(data.email, 128).toLowerCase();
      const name = clean(data.name, 256);

      if (form === "waitlist" || form === "beta") {
        if (!validEmail(email)) {
          return json(
            { error: "Valid email required" },
            400,
            cors
          );
        }

        await env.DB.prepare(`
          INSERT OR IGNORE INTO waitlist
          (
            email,
            name,
            resale_category,
            signup_source,
            marketing_consent
          )
          VALUES (?, ?, ?, ?, ?)
        `).bind(
          email,
          name,
          clean(data.resale_category, 100),
          clean(data.signup_source, 100) || "website",
          data.marketing_consent === true ? 1 : 0
        ).run();

      } else if (form === "partner") {
        const handle = clean(data.primary_handle, 256);

        const resaleCategory = clean(data.resale_category, 100);

        if (!name || !handle || !validEmail(email) || !resaleCategory) {
          return json(
            { error: "Name, valid contact email, handle, and resale category required" },
            400,
            cors
          );
        }

        const audience = Number(data.audience_size);

        await env.DB.prepare(`
          INSERT INTO partner_applications
          (
            name,
            email,
            primary_handle,
            core_channel,
            audience_size,
            resale_category,
            sourcing_focus,
            application_message
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          name,
          email,
          handle,
          clean(data.core_channel, 100),
          Number.isSafeInteger(audience) && audience >= 0
            ? audience
            : null,
          resaleCategory,
          clean(data.sourcing_focus, 100),
          clean(data.application_message, 2000)
        ).run();

      } else if (form === "founder") {
        const message = clean(data.message, 2000);

        if (!message) {
          return json(
            { error: "Message required" },
            400,
            cors
          );
        }

        if (email && !validEmail(email)) {
          return json(
            { error: "Invalid email" },
            400,
            cors
          );
        }

        await env.DB.prepare(`
          INSERT INTO founder_messages
          (name, email, message)
          VALUES (?, ?, ?)
        `).bind(
          name,
          email || null,
          message
        ).run();

      } else {
        return json(
          { error: "Unknown form" },
          400,
          cors
        );
      }

      // Email failure will not lose the submission.
      try {
        await sendSignupNotification(env, data);
      } catch (error) {
        console.error(
          "Email notification failed:",
          error.message
        );
      }

      return json(
        {
          success: true,
          message: "Submission received"
        },
        200,
        cors
      );

    } catch (error) {
      console.error(
        "Form processing failed:",
        error.name
      );

      return json(
        { error: "Submission failed" },
        500,
        cors
      );
    }
  }
};
