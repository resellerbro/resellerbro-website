/* Reseller Bro website forms: Turnstile + Cloudflare Forms Worker. */
(() => {
  "use strict";
  const ENDPOINT = "https://resellerbro-formsa.gisttttt.workers.dev/";
  const SITE_KEY = "0x4AAAAAAFykgnfJ4h7h9FiK";
  const definitions = {
    form01: () => ({ form: "founder", message: document.getElementById("form01-ama").value }),
    form02: () => ({ form: "beta", name: document.getElementById("form02-name").value, email: document.getElementById("form02-email").value, resale_category: document.getElementById("form02-iama").value, signup_source: "founder-signup" }),
    form03: () => ({ form: "partner", name: document.getElementById("form03-creativeAlias").value, primary_handle: document.getElementById("form03-primaryHandle").value, core_channel: document.getElementById("form03-coreChannel").value, audience_size: document.getElementById("form03-audienceSize").value, sourcing_focus: document.getElementById("form03-sourcingFocus").value, application_message: document.getElementById("form03-whyFoundingPartner").value }),
    form04: () => ({ form: "waitlist", email: document.getElementById("form04-email").value, signup_source: "website-waitlist" })
  };
  function init() {
    Object.entries(definitions).forEach(([id, getPayload]) => {
      const form = document.getElementById(id);
      if (!form) return;
      const button = form.querySelector('button[type="submit"]');
      if (!button) return;
      const container = document.createElement("div");
      container.style.cssText = "margin:12px 0;min-height:65px;";
      const status = document.createElement("p");
      status.setAttribute("role", "status");
      status.setAttribute("aria-live", "polite");
      status.style.cssText = "margin:10px 0;color:#fff;font-size:14px;";
      button.parentElement.before(container);
      button.parentElement.after(status);
      let widgetId;
      if (window.turnstile) widgetId = window.turnstile.render(container, { sitekey: SITE_KEY, theme: "dark" });
      else status.textContent = "Security verification unavailable. Please reload the page.";
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        event.stopImmediatePropagation();
        if (!form.reportValidity()) return;
        const token = window.turnstile && widgetId !== undefined ? window.turnstile.getResponse(widgetId) : "";
        if (!token) { status.textContent = "Please complete the security verification."; return; }
        button.disabled = true;
        status.textContent = "Sending...";
        try {
          const response = await fetch(ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...getPayload(), turnstileToken: token, website: "" })
          });
          const result = await response.json();
          if (!response.ok || !result.success) throw new Error(result.error || "Submission failed");
          status.textContent = "Thanks! Your submission was received.";
          form.reset();
        } catch (error) {
          status.textContent = "Unable to submit right now. Please try again.";
          console.error("Reseller Bro form error:", error);
        } finally {
          button.disabled = false;
          if (window.turnstile && widgetId !== undefined) window.turnstile.reset(widgetId);
        }
      }, true);
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
