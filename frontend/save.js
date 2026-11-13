// Standalone backend Save handler.
(function () {
  function initBackendSave() {
    const button = document.getElementById("saveApi");
    const input = document.getElementById("apiUrl");
    const status = document.getElementById("apiMessage");
    if (!button || !input || !status || button.dataset.saveBound === "1") return;
    button.dataset.saveBound = "1";
    const saved = localStorage.getItem("bugHunterApiUrl") || "";
    if (saved && !input.value) input.value = saved;
    button.addEventListener("click", async function (event) {
      event.preventDefault();
      const value = input.value.trim().replace(/\/+$/, "");
      if (!value) { status.textContent = "Enter your backend API URL first."; status.className = "message error"; return; }
      let parsed;
      try { parsed = new URL(value); } catch (_) { status.textContent = "Enter a valid backend URL."; status.className = "message error"; return; }
      if (!["https:", "http:"].includes(parsed.protocol)) { status.textContent = "Backend URL must start with https:// or http://"; status.className = "message error"; return; }
      localStorage.setItem("bugHunterApiUrl", value);
      status.textContent = "Backend URL saved. Checking connection…";
      status.className = "message";
      try {
        const response = await fetch(value + "/health", { method: "GET", cache: "no-store" });
        if (!response.ok) throw new Error("HTTP " + response.status);
        const data = await response.json();
        if (data.status !== "ok") throw new Error("Unexpected health response");
        status.textContent = "✓ Connected successfully. Backend is ready for scanning.";
        status.className = "message success";
      } catch (error) {
        status.textContent = "URL saved, but connection check failed: " + (error.message || "Network/CORS error") + ".";
        status.className = "message error";
      }
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initBackendSave);
  else initBackendSave();
})();