// ============================================================
// INPUT VALIDATION
// ============================================================
function isValidIP(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;

  if (ipv4Regex.test(ip)) {
    const parts = ip.split(".").map(Number);

    if (
      parts.every(
        octet => octet >= 0 && octet <= 255
      )
    ) {
      return (
        ipaddr.isValid(ip) &&
        ipaddr.parse(ip).kind() === "ipv4"
      );
    }

    return false;
  }

  if (ipaddr.isValid(ip)) {
    return (
      ipaddr.parse(ip).kind() === "ipv6"
    );
  }

  return false;
}

function isValidHash(str) {
  const s = str.toLowerCase();

  return (
    /^[a-f0-9]{32}$/.test(s) ||
    /^[a-f0-9]{40}$/.test(s) ||
    /^[a-f0-9]{64}$/.test(s)
  );
}

function isPrivateIP(ip) {
  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(isNaN)
  ) {
    return false;
  }

  const [a, b] = parts;

  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

// ============================================================
// URL VALIDATION
// ============================================================
function isValidURL(str) {
  try {
    const url = new URL(
      str.startsWith("http://") ||
      str.startsWith("https://")
        ? str
        : `http://${str}`
    );

    const hostname = url.hostname;

    // Reject obvious IPv4 addresses
    if (
      /^\d{1,3}(\.\d{1,3}){1,2}$/.test(
        hostname
      )
    ) {
      return false;
    }

    // Hostname must contain a dot
    if (!hostname.includes(".")) {
      return false;
    }

    // Basic TLD validation
    if (
      !/[a-zA-Z]{2,}$/.test(
        hostname.split(".").pop()
      )
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

// ============================================================
// EXTRACT HOSTNAME / DOMAIN
// ============================================================
// Examples:
//
// https://api.npoint.io/987u89893u83985798
// → api.npoint.io
//
// http://www.example.com/login?id=123
// → www.example.com
//
// example.com/path/test
// → example.com
// ============================================================
function extractHostname(str) {
  try {
    const url = new URL(
      str.startsWith("http://") ||
      str.startsWith("https://")
        ? str
        : `http://${str}`
    );

    return url.hostname.toLowerCase();
  } catch {
    return null;
  }
}

// ============================================================
// DYNAMIC INPUT TYPE HEADER
// ============================================================
function getDynamicInputHeader(rows) {
  const types = new Set();

  for (const row of rows || []) {
    const value =
      String(row?.[0] ?? "").trim();

    if (!value) {
      continue;
    }

    if (isValidIP(value)) {
      types.add("IP");
    } else if (isValidURL(value)) {
      types.add("URL");
    } else if (isValidHash(value)) {
      types.add("HASH");
    }
  }

  const order = [
    "IP",
    "URL",
    "HASH"
  ];

  return (
    order
      .filter(type => types.has(type))
      .join(" / ") ||
    "IP"
  );
}

// ============================================================
// API KEY INPUT HELPERS
// ============================================================
function getApiKeyValue(ids) {
  for (const id of ids) {
    const element =
      document.getElementById(id);

    if (element) {
      return element.value.trim();
    }
  }

  return "";
}

function getUserApiKeys() {
  return {
    vt_api_key: getApiKeyValue([
      "vtApiKey",
      "vt_api_key",
      "virustotalApiKey",
      "virustotal_api_key"
    ]),

    apivoid_api_key: getApiKeyValue([
      "apivoidApiKey",
      "apivoid_api_key",
      "apiVoidApiKey",
      "apiVoid_api_key"
    ]),

    abuseipdb_api_key: getApiKeyValue([
      "abuseipdbApiKey",
      "abuseipdb_api_key",
      "abuseApiKey",
      "abuse_api_key"
    ])
  };
}

// ============================================================
// API KEY MASKING
// ============================================================
function maskApiKey(key) {
  if (!key) {
    return "••••";
  }

  const value = key.trim();

  if (value.length <= 8) {
    return "••••••••";
  }

  const start = value.slice(0, 4);
  const end = value.slice(-4);

  return `${start}••••••••${end}`;
}

// ============================================================
// SERVICE NAME HELPERS
// ============================================================
function getServiceKeyName(service) {
  if (service === "VirusTotal") {
    return "vt_api_key";
  }

  if (service === "APIVoid") {
    return "apivoid_api_key";
  }

  if (service === "AbuseIPDB") {
    return "abuseipdb_api_key";
  }

  return null;
}

function getServiceDisplayName(service) {
  const names = {
    VirusTotal: "VirusTotal",
    APIVoid: "APIVoid",
    AbuseIPDB: "AbuseIPDB"
  };

  return names[service] || service;
}

// ============================================================
// API KEY INPUT BEAUTIFICATION
// ============================================================
function styleApiKeyInputs() {
  const selectors = [
    "#vtApiKey",
    "#vt_api_key",
    "#virustotalApiKey",
    "#virustotal_api_key",
    "#apivoidApiKey",
    "#apivoid_api_key",
    "#apiVoidApiKey",
    "#apiVoid_api_key",
    "#abuseipdbApiKey",
    "#abuseipdb_api_key",
    "#abuseApiKey",
    "#abuse_api_key"
  ];

  selectors.forEach(selector => {
    const input =
      document.querySelector(selector);

    if (!input) {
      return;
    }

    input.style.color = "#e5e7eb";
    input.style.caretColor = "#60a5fa";
    input.style.backgroundColor =
      "rgba(17, 24, 39, 0.85)";
    input.style.border =
      "1px solid rgba(148, 163, 184, 0.25)";
    input.style.transition =
      "all 0.2s ease";
    input.style.padding =
      "10px 12px";
    input.style.borderRadius =
      "8px";
    input.style.outline = "none";

    input.addEventListener(
      "focus",
      () => {
        input.style.border =
          "1px solid #60a5fa";

        input.style.boxShadow =
          "0 0 0 3px rgba(96,165,250,0.12)";
      }
    );

    input.addEventListener(
      "blur",
      () => {
        input.style.border =
          "1px solid rgba(148,163,184,0.25)";

        input.style.boxShadow =
          "none";
      }
    );

    input.addEventListener(
      "input",
      () => {
        if (input.value.trim()) {
          input.style.border =
            "1px solid rgba(34,197,94,0.65)";

          input.style.boxShadow =
            "0 0 10px rgba(34,197,94,0.10)";
        } else {
          input.style.border =
            "1px solid rgba(148,163,184,0.25)";

          input.style.boxShadow =
            "none";
        }
      }
    );
  });
}

// ============================================================
// INVALID API KEY POPUP
// ============================================================
function showInvalidApiKeyPopup(
  invalidKeyItems
) {
  if (
    !Array.isArray(invalidKeyItems) ||
    invalidKeyItems.length === 0
  ) {
    return Promise.resolve(null);
  }

  return new Promise(resolve => {
    const existing =
      document.getElementById(
        "invalidApiKeyPopup"
      );

    if (existing) {
      existing.remove();
    }

    const item =
      invalidKeyItems[0];

    const service =
      item.service || "API Service";

    const originalKey =
      item.api_key ||
      item.key ||
      item.value ||
      "";

    const maskedKey =
      item.masked_key ||
      maskApiKey(originalKey);

    const overlay =
      document.createElement("div");

    overlay.id =
      "invalidApiKeyPopup";

    overlay.style.position =
      "fixed";

    overlay.style.inset =
      "0";

    overlay.style.background =
      "rgba(0, 0, 0, 0.72)";

    overlay.style.backdropFilter =
      "blur(5px)";

    overlay.style.display =
      "flex";

    overlay.style.alignItems =
      "center";

    overlay.style.justifyContent =
      "center";

    overlay.style.zIndex =
      "99999";

    overlay.style.padding =
      "20px";

    const popup =
      document.createElement("div");

    popup.style.width =
      "min(520px, 94%)";

    popup.style.padding =
      "26px";

    popup.style.borderRadius =
      "14px";

    popup.style.background =
      "#111827";

    popup.style.color =
      "#ffffff";

    popup.style.border =
      "1px solid rgba(148,163,184,0.25)";

    popup.style.boxShadow =
      "0 25px 70px rgba(0,0,0,0.65)";

    popup.innerHTML = `
      <div style="
        display:flex;
        align-items:center;
        gap:12px;
        margin-bottom:16px;
      ">
        <div style="
          width:42px;
          height:42px;
          border-radius:50%;
          display:flex;
          align-items:center;
          justify-content:center;
          background:rgba(239,68,68,0.12);
          color:#f87171;
          font-size:22px;
        ">
          ⚠️
        </div>

        <div>
          <h3 style="
            margin:0;
            font-size:20px;
            font-weight:700;
          ">
            API Key Rejected
          </h3>

          <div style="
            margin-top:3px;
            font-size:13px;
            color:#9ca3af;
          ">
            ${getServiceDisplayName(service)}
          </div>
        </div>
      </div>

      <div style="
        padding:12px 14px;
        border-radius:8px;
        background:rgba(239,68,68,0.08);
        border:1px solid rgba(239,68,68,0.18);
        margin-bottom:16px;
      ">
        <div style="
          font-size:13px;
          color:#9ca3af;
          margin-bottom:5px;
        ">
          Rejected key
        </div>

        <div style="
          font-family:monospace;
          color:#fca5a5;
          word-break:break-all;
        ">
          ${maskedKey}
        </div>
      </div>

      <p style="
        margin:0 0 8px;
        line-height:1.55;
        color:#e5e7eb;
      ">
        The API key entered for
        <strong>${service}</strong>
        was rejected.
      </p>

      <p style="
        margin:0 0 20px;
        line-height:1.55;
        color:#9ca3af;
        font-size:14px;
      ">
        Choose what you want to do.
        The system will <strong>not</strong>
        automatically switch to the default key.
      </p>

      <div style="
        display:flex;
        gap:10px;
        justify-content:flex-end;
        flex-wrap:wrap;
      ">
        <button
          id="apiKeyUseExistingBtn"
          style="
            padding:10px 16px;
            border-radius:8px;
            border:none;
            cursor:pointer;
            background:#2563eb;
            color:white;
            font-weight:600;
          "
        >
          Use Existing Key
        </button>

        <button
          id="apiKeyEnterNewBtn"
          style="
            padding:10px 16px;
            border-radius:8px;
            border:none;
            cursor:pointer;
            background:#7c3aed;
            color:white;
            font-weight:600;
          "
        >
          Enter Another Key
        </button>
      </div>
    `;

    overlay.appendChild(popup);
    document.body.appendChild(
      overlay
    );

    document
      .getElementById(
        "apiKeyUseExistingBtn"
      )
      .addEventListener(
        "click",
        () => {
          overlay.remove();

          resolve({
            action: "use_default",
            service: service,
            rejectedKey: originalKey,
            maskedKey: maskedKey
          });
        }
      );

    document
      .getElementById(
        "apiKeyEnterNewBtn"
      )
      .addEventListener(
        "click",
        () => {
          overlay.remove();

          resolve({
            action: "enter_new",
            service: service,
            rejectedKey: originalKey,
            maskedKey: maskedKey
          });
        }
      );
  });
}

// ============================================================
// ASK FOR A NEW API KEY
// ============================================================
function askForNewApiKey(service) {
  return new Promise(resolve => {
    const existing =
      document.getElementById(
        "enterNewApiKeyPopup"
      );

    if (existing) {
      existing.remove();
    }

    const overlay =
      document.createElement("div");

    overlay.id =
      "enterNewApiKeyPopup";

    overlay.style.position =
      "fixed";

    overlay.style.inset =
      "0";

    overlay.style.background =
      "rgba(0,0,0,0.72)";

    overlay.style.backdropFilter =
      "blur(5px)";

    overlay.style.display =
      "flex";

    overlay.style.alignItems =
      "center";

    overlay.style.justifyContent =
      "center";

    overlay.style.zIndex =
      "100000";

    overlay.style.padding =
      "20px";

    const popup =
      document.createElement("div");

    popup.style.width =
      "min(500px,94%)";

    popup.style.padding =
      "26px";

    popup.style.borderRadius =
      "14px";

    popup.style.background =
      "#111827";

    popup.style.color =
      "#ffffff";

    popup.style.border =
      "1px solid rgba(148,163,184,0.25)";

    popup.style.boxShadow =
      "0 25px 70px rgba(0,0,0,0.65)";

    popup.innerHTML = `
      <h3 style="
        margin:0 0 8px;
        font-size:20px;
        font-weight:700;
      ">
        🔑 Enter Another ${service} Key
      </h3>

      <p style="
        margin:0 0 18px;
        color:#9ca3af;
        font-size:14px;
        line-height:1.5;
      ">
        Enter a new API key below.
        This key will be tested before
        any fallback to the system key occurs.
      </p>

      <input
        id="newApiKeyInput"
        type="password"
        autocomplete="off"
        spellcheck="false"
        placeholder="Enter your ${service} API key"
        style="
          width:100%;
          box-sizing:border-box;
          padding:12px 14px;
          border-radius:9px;
          border:1px solid rgba(148,163,184,0.3);
          background:#0f172a;
          color:#f8fafc;
          caret-color:#60a5fa;
          outline:none;
          font-family:monospace;
          font-size:14px;
        "
      />

      <div
        id="newApiKeyError"
        style="
          display:none;
          margin-top:10px;
          color:#f87171;
          font-size:13px;
        "
      >
      </div>

      <div style="
        display:flex;
        justify-content:flex-end;
        gap:10px;
        margin-top:20px;
      ">
        <button
          id="cancelNewApiKeyBtn"
          style="
            padding:10px 16px;
            border-radius:8px;
            border:1px solid rgba(148,163,184,0.25);
            cursor:pointer;
            background:#1f2937;
            color:#d1d5db;
            font-weight:600;
          "
        >
          Back
        </button>

        <button
          id="submitNewApiKeyBtn"
          style="
            padding:10px 16px;
            border-radius:8px;
            border:none;
            cursor:pointer;
            background:#7c3aed;
            color:white;
            font-weight:600;
          "
        >
          Test Key
        </button>
      </div>
    `;

    overlay.appendChild(popup);
    document.body.appendChild(
      overlay
    );

    const input =
      document.getElementById(
        "newApiKeyInput"
      );

    const error =
      document.getElementById(
        "newApiKeyError"
      );

    setTimeout(
      () => input.focus(),
      50
    );

    input.addEventListener(
      "focus",
      () => {
        input.style.border =
          "1px solid #60a5fa";

        input.style.boxShadow =
          "0 0 0 3px rgba(96,165,250,0.12)";
      }
    );

    input.addEventListener(
      "blur",
      () => {
        input.style.border =
          "1px solid rgba(148,163,184,0.3)";

        input.style.boxShadow =
          "none";
      }
    );

    document
      .getElementById(
        "submitNewApiKeyBtn"
      )
      .addEventListener(
        "click",
        () => {
          const value =
            input.value.trim();

          if (!value) {
            error.textContent =
              "Please enter an API key.";

            error.style.display =
              "block";

            input.focus();

            return;
          }

          overlay.remove();

          resolve({
            action: "new_key",
            key: value
          });
        }
      );

    document
      .getElementById(
        "cancelNewApiKeyBtn"
      )
      .addEventListener(
        "click",
        () => {
          overlay.remove();

          resolve({
            action: "back"
          });
        }
      );

    input.addEventListener(
      "keydown",
      event => {
        if (
          event.key === "Enter"
        ) {
          event.preventDefault();

          document
            .getElementById(
              "submitNewApiKeyBtn"
            )
            .click();
        }
      }
    );
  });
}

// ============================================================
// FETCH IP / DOMAIN / HASH DATA
// ============================================================
async function fetchIPData() {
  const inputField =
    document.getElementById(
      "ipInput"
    );

  const lookupButton =
    document.getElementById(
      "lookupButton"
    );

  const summaryDiv =
    document.getElementById(
      "summary"
    );

  const tableBody =
    document.getElementById(
      "tableBody"
    );

  const summarySection =
    document.getElementById(
      "summarySection"
    );

  const tableSection =
    document.getElementById(
      "tableSection"
    );

  const errorMsg =
    document.getElementById(
      "errorMsg"
    );

  const messageDiv =
    document.getElementById(
      "message"
    );

  const messageBlock =
    document.getElementById(
      "messageBlock"
    );

  const downloadBtn =
    document.getElementById(
      "downloadExcelBtn"
    );

  // ==========================================================
  // RESET PREVIOUS RESULT
  // ==========================================================
  errorMsg.classList.add(
    "hidden"
  );

  summarySection.classList.add(
    "hidden"
  );

  tableSection.classList.add(
    "hidden"
  );

  summaryDiv.textContent =
    "";

  tableBody.innerHTML =
    "";

  downloadBtn.style.display =
    "none";

  messageDiv.innerHTML =
    "";

  messageBlock.classList.remove(
    "show",
    "hidden"
  );

  // ==========================================================
  // PARSE INPUT
  // ==========================================================
  const rawEntries =
    inputField.value
      .split(/[\s,\n]+/)
      .map(e => e.trim())
      .filter(
        e => e.length > 0
      );

  const seen =
    new Set();

  const validIPs =
    [];

  const validDomains =
    [];

  const validHashes =
    [];

  const skippedInvalid =
    [];

  const duplicates =
    [];

  // ==========================================================
  // VALIDATE + NORMALIZE + DEDUPLICATE
  // ==========================================================
  for (const entry of rawEntries) {

    // --------------------------------------------------------
    // IP
    // --------------------------------------------------------
    if (isValidIP(entry)) {

      if (seen.has(entry)) {
        duplicates.push(entry);
        continue;
      }

      seen.add(entry);

      if (!isPrivateIP(entry)) {
        validIPs.push(entry);
      }

      continue;
    }

    // --------------------------------------------------------
    // URL → HOSTNAME
    // --------------------------------------------------------
    if (isValidURL(entry)) {

      const hostname =
        extractHostname(entry);

      if (!hostname) {
        skippedInvalid.push(entry);
        continue;
      }

      // ------------------------------------------------------
      // IMPORTANT:
      // Duplicate check happens AFTER hostname extraction.
      //
      // Example:
      //
      // https://api.npoint.io/abc
      // https://api.npoint.io/xyz
      // http://api.npoint.io/test
      // api.npoint.io/path
      //
      // All normalize to:
      //
      // api.npoint.io
      //
      // Only the first one is processed.
      // ------------------------------------------------------
      if (seen.has(hostname)) {
        duplicates.push(entry);
        continue;
      }

      seen.add(hostname);

      validDomains.push(hostname);

      continue;
    }

    // --------------------------------------------------------
    // HASH
    // --------------------------------------------------------
    if (isValidHash(entry)) {

      const normalizedHash =
        entry.toLowerCase();

      if (seen.has(normalizedHash)) {
        duplicates.push(entry);
        continue;
      }

      seen.add(normalizedHash);

      validHashes.push(
        normalizedHash
      );

      continue;
    }

    // --------------------------------------------------------
    // INVALID
    // --------------------------------------------------------
    skippedInvalid.push(entry);
  }

  // ==========================================================
  // COMBINE VALID ENTRIES
  // ==========================================================
  let validEntries = [
    ...validIPs,
    ...validDomains,
    ...validHashes
  ];

  const messages =
    [];

  // ==========================================================
  // NO VALID INPUT
  // ==========================================================
  if (
    validEntries.length === 0
  ) {
    errorMsg.textContent =
      "⚠️ No valid public IPs, domains or hashes found.";

    errorMsg.classList.remove(
      "hidden"
    );

    return;
  }

  // ==========================================================
  // INVALID ENTRIES
  // ==========================================================
  if (
    skippedInvalid.length > 0
  ) {
    messages.push(
      `⚠️ <span class="text-red-400 font-bold glow-red">${
        skippedInvalid.length
      } Invalid entr${
        skippedInvalid.length !== 1
          ? "ies"
          : "y"
      } skipped</span>: ${
        skippedInvalid.join(", ")
      }`
    );
  }

  // ==========================================================
  // DUPLICATES
  // ==========================================================
  if (
    duplicates.length > 0
  ) {
    messages.push(
      `⚠️ <span class="text-red-400 font-bold glow-red">${
        duplicates.length
      } Duplicate${
        duplicates.length !== 1
          ? "s"
          : ""
      } removed</span>: ${
        duplicates.join(", ")
      }`
    );
  }

  // ==========================================================
  // PRIVATE IPs
  // ==========================================================
  const privateIPs =
    rawEntries.filter(
      ip =>
        isValidIP(ip) &&
        isPrivateIP(ip)
    );

  if (
    privateIPs.length > 0
  ) {
    messages.push(
      `⚠️ <span class="text-red-400 font-bold glow-red">${
        privateIPs.length
      } Private/reserved IP${
        privateIPs.length !== 1
          ? "s"
          : ""
      } filtered</span>: ${
        privateIPs.join(", ")
      }`
    );
  }

  // ==========================================================
  // MAX 100
  // ==========================================================
  if (
    validEntries.length > 100
  ) {
    messages.push(
      `⚠️ You entered <span class="text-green-400 font-bold">${
        validEntries.length
      }</span> valid entries. Only the first 100 will be processed.`
    );

    messages.push(
      `⚠️ <span class="text-purple-400 font-bold">${
        validEntries.length - 100
      } entries skipped</span>: ${
        validEntries
          .slice(100)
          .join(", ")
      }`
    );

    validEntries =
      validEntries.slice(
        0,
        100
      );
  }

  // ==========================================================
  // BUTTON STATE
  // ==========================================================
  lookupButton.disabled =
    true;

  lookupButton.textContent =
    "Fetching...";

  // ==========================================================
  // GET USER API KEYS
  // ==========================================================
  let userApiKeys =
    getUserApiKeys();

  // ==========================================================
  // KEEP TRACK OF FALLBACKS
  // ==========================================================
  const fallbackMessages =
    [];

  // ==========================================================
  // REQUEST FUNCTION
  // ==========================================================
  async function performLookup(
    apiKeys
  ) {
    const response =
      await fetch(
        "/get_ip_info",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            // Keeping "ips" here so your
            // existing Flask backend does
            // not need to be changed.
            //
            // It now contains:
            // IPs + normalized hostnames + hashes
            ips:
              validEntries,

            api_keys: {
              vt:
                apiKeys.vt_api_key,

              apivoid:
                apiKeys.apivoid_api_key,

              abuseipdb:
                apiKeys.abuseipdb_api_key
            }
          })
        }
      );

    if (
      !response.ok
    ) {
      const error =
        await response
          .json()
          .catch(
            () => ({})
          );

      throw new Error(
        error.error ||
        "Server error occurred."
      );
    }

    return response.json();
  }

  // ==========================================================
  // API KEY HANDLING
  // ==========================================================
  async function lookupWithApiKeyHandling() {
    while (true) {

      const data =
        await performLookup(
          userApiKeys
        );

      const errors =
        Array.isArray(
          data.user_key_errors
        )
          ? data.user_key_errors
          : [];

      if (
        errors.length === 0
      ) {
        return data;
      }

      const invalidItem =
        errors[0];

      const service =
        invalidItem.service ||
        "API Service";

      const keyName =
        getServiceKeyName(
          service
        );

      if (!keyName) {
        console.warn(
          "Unknown API service:",
          service
        );

        return data;
      }

      const rejectedKey =
        userApiKeys[keyName] ||
        invalidItem.api_key ||
        invalidItem.key ||
        "";

      const maskedRejectedKey =
        maskApiKey(
          rejectedKey
        );

      const choice =
        await showInvalidApiKeyPopup([
          {
            ...invalidItem,

            service:
              service,

            api_key:
              rejectedKey,

            masked_key:
              maskedRejectedKey
          }
        ]);

      // --------------------------------------------------------
      // USE DEFAULT SYSTEM KEY
      // --------------------------------------------------------
      if (
        choice &&
        choice.action ===
          "use_default"
      ) {
        fallbackMessages.push(
          `⚠️ <strong>${service}</strong> API key <code>${maskedRejectedKey}</code> was rejected. Default system key was used instead.`
        );

        userApiKeys[keyName] =
          "";

        continue;
      }

      // --------------------------------------------------------
      // ENTER NEW KEY
      // --------------------------------------------------------
      if (
        choice &&
        choice.action ===
          "enter_new"
      ) {
        const newKeyResult =
          await askForNewApiKey(
            service
          );

        if (
          newKeyResult.action ===
          "back"
        ) {
          continue;
        }

        if (
          newKeyResult.action ===
          "new_key"
        ) {
          const newKey =
            newKeyResult.key.trim();

          userApiKeys[keyName] =
            newKey;

          continue;
        }
      }
    }
  }

  // ==========================================================
  // MAIN REQUEST
  // ==========================================================
  try {

    const data =
      await lookupWithApiKeyHandling();

    // ========================================================
    // PROCESSED COUNT
    // ========================================================
    const processedCount =
      data.raw_table?.length ||
      0;

    // ========================================================
    // DYNAMIC HEADER
    // ========================================================
    const dynamicInputHeader =
      getDynamicInputHeader(
        data.raw_table || []
      );

    // ========================================================
    // SUMMARY
    // ========================================================
    summaryDiv.innerHTML =
      data.summary;

    // ========================================================
    // EXHAUSTED SERVICES
    // ========================================================
    if (
      Array.isArray(
        data.exhausted_messages
      ) &&
      data.exhausted_messages.length > 0
    ) {
      data.exhausted_messages
        .forEach(
          msg => {
            messages.push(
              `<div class="font-medium mb-3 text-red-600">${msg}</div>`
            );
          }
        );
    }

    // ========================================================
    // NO DATA
    // ========================================================
    if (
      Array.isArray(
        data.no_data_ips
      ) &&
      data.no_data_ips.length > 0
    ) {

      const returnedEntries =
        new Set(
          (data.raw_table || [])
            .map(row =>
              row &&
              row.length > 0
                ? String(
                    row[0]
                  ).trim()
                : ""
            )
            .filter(Boolean)
        );

      const actualNoData =
        data.no_data_ips.filter(
          entry =>
            !returnedEntries.has(
              String(
                entry
              ).trim()
            )
        );

      if (
        actualNoData.length > 0
      ) {

        const displayList =
          actualNoData
            .slice(0, 5)
            .join(", ");

        const more =
          actualNoData.length > 5
            ? ` and ${
                actualNoData.length - 5
              } more...`
            : "";

        messages.push(
          `⚠️ ${
            actualNoData.length
          } entr${
            actualNoData.length !== 1
              ? "ies"
              : "y"
          } returned no fields: ${
            displayList
          }${more}`
        );
      }
    }

    // ========================================================
    // USER KEY MESSAGES FROM BACKEND
    // ========================================================
    if (
      Array.isArray(
        data.user_key_messages
      ) &&
      data.user_key_messages.length > 0
    ) {

      data.user_key_messages
        .forEach(
          msg => {
            messages.push(
              `<div class="font-medium mb-3 text-blue-400">${msg}</div>`
            );
          }
        );
    }

    // ========================================================
    // FALLBACK MESSAGES
    // ========================================================
    fallbackMessages.forEach(
      msg => {
        messages.push(
          `<div class="font-medium mb-3 text-yellow-400">${msg}</div>`
        );
      }
    );

    // ========================================================
    // ENTRY MESSAGE
    // ========================================================
    const entryMsg =
      `✅ Data found for <span class="text-green-400 font-bold">${
        processedCount
      } entr${
        processedCount !== 1
          ? "ies"
          : "y"
      }</span> in <span class="text-blue-400 font-bold">${
        data.elapsed
      } second${
        data.elapsed !== 1
          ? "s"
          : ""
      }</span>.`;

    // ========================================================
    // SERVICES USED
    // ========================================================
    const serviceList =
      Array.isArray(
        data.services_used
      )
        ? data.services_used
        : [];

    const serviceMsg =
      `🔧 Service${
        serviceList.length !== 1
          ? "s"
          : ""
      } used: <span class="text-purple-400 font-bold">${
        serviceList.join(", ") ||
        "None"
      }</span>`;

    messages.unshift(
      serviceMsg
    );

    messages.unshift(
      entryMsg
    );

    // ========================================================
    // TABLE HEADER
    // ========================================================
    const tableHead =
      document.getElementById(
        "tableHead"
      );

    tableHead.innerHTML =
      "";

    const headerRow =
      document.createElement(
        "tr"
      );

    const headerTitles = [
      dynamicInputHeader,
      "ISP",
      "Country",
      "VT Detection Count",
      "APIVoid Risk Score",
      "APIVoid Detections Count",
      "AbuseIPDB Confidence Score(%)",
      "AbuseIPDB Report Count"
    ];

    for (
      const title of headerTitles
    ) {

      const th =
        document.createElement(
          "th"
        );

      th.innerText =
        title;

      th.className =
        "border px-3 py-2 text-center";

      headerRow.appendChild(
        th
      );
    }

    tableHead.appendChild(
      headerRow
    );

    // ========================================================
    // TABLE BODY
    // ========================================================
    tableBody.innerHTML =
      "";

    for (
      const row of
      data.raw_table || []
    ) {

      const [
        inputValue,
        isp,
        country,
        detections,
        apivoidRiskScore,
        apivoidBlacklistDetections,
        abuseipdbConfidenceRaw,
        abuseipdbReportCountRaw
      ] = row;

      function formatField(
        field
      ) {

        if (
          field === null ||
          field === undefined ||
          field === ""
        ) {
          return "-";
        }

        if (
          Array.isArray(field)
        ) {
          return field.length
            ? field.join(", ")
            : "-";
        }

        return field.toString();
      }

      const cells = [
        inputValue,
        formatField(isp),
        formatField(country),
        formatField(
          detections
        ),
        formatField(
          apivoidRiskScore
        ),
        formatField(
          apivoidBlacklistDetections
        ),
        formatField(
          abuseipdbConfidenceRaw
        ),
        formatField(
          abuseipdbReportCountRaw
        )
      ];

      const tr =
        document.createElement(
          "tr"
        );

      for (
        const cell of cells
      ) {

        const td =
          document.createElement(
            "td"
          );

        td.innerText =
          cell;

        td.className =
          "border px-3 py-1 text-center";

        tr.appendChild(
          td
        );
      }

      tableBody.appendChild(
        tr
      );
    }

    // ========================================================
    // SHOW RESULTS
    // ========================================================
    summarySection.classList.remove(
      "hidden"
    );

    tableSection.classList.remove(
      "hidden"
    );

    messageBlock.style.display =
      "block";

    messageDiv.innerHTML =
      messages
        .map(
          m =>
            `<div class="font-medium mb-3">${m}</div>`
        )
        .join("");

    requestAnimationFrame(
      () => {

        summarySection.classList.add(
          "show"
        );

        tableSection.classList.add(
          "show"
        );

        messageBlock.classList.add(
          "show"
        );
      }
    );

    // ========================================================
    // DOWNLOAD
    // ========================================================
    downloadBtn.style.display =
      "inline-block";

    document
      .getElementById(
        "resetContainer"
      )
      .classList.remove(
        "hidden"
      );

    // ========================================================
    // STORE LATEST DATA
    // ========================================================
    window._latestSummary =
      data.summary;

    window._latestTable =
      data.raw_table;

    window._columnLabel =
      dynamicInputHeader;

  } catch (err) {

    console.error(
      "Error:",
      err
    );

    alert(
      "❌ Error retrieving data:\n" +
      err.message
    );

  } finally {

    lookupButton.disabled =
      false;

    lookupButton.textContent =
      "Get Info";
  }
}

// ============================================================
// COPY SUMMARY
// ============================================================
function copyToClipboard(
  elementId,
  btnId
) {
  const text =
    document.getElementById(
      elementId
    ).innerText;

  navigator.clipboard
    .writeText(text)
    .then(
      () => {

        const btn =
          document.getElementById(
            btnId
          );

        const original =
          btn.innerHTML;

        btn.innerHTML =
          '<i class="ph ph-check"></i> Copied!';

        setTimeout(
          () =>
            (
              btn.innerHTML =
                original
            ),
          1500
        );
      }
    );
}

// ============================================================
// COPY TABLE
// ============================================================
function copyTableToClipboard(
  btnId
) {
  const headers =
    [
      ...document.querySelectorAll(
        "#tableSection thead th"
      )
    ]
      .map(
        th =>
          th.innerText.trim()
      )
      .join("\t");

  const rows =
    [
      ...document.querySelectorAll(
        "#tableBody tr"
      )
    ]
      .map(
        row => {

          const cells =
            [
              ...row.children
            ]
              .map(
                (cell, i) => {

                  let text =
                    cell.innerText.trim();

                  if (
                    i === 3
                  ) {
                    text =
                      `"${text}"`;
                  }

                  return text;
                }
              );

          return cells.join(
            "\t"
          );
        }
      );

  const text =
    [
      headers,
      ...rows
    ].join("\n");

  navigator.clipboard
    .writeText(text)
    .then(
      () => {

        const btn =
          document.getElementById(
            btnId
          );

        const original =
          btn.innerHTML;

        btn.innerHTML =
          '<i class="ph ph-check"></i> Copied!';

        setTimeout(
          () =>
            (
              btn.innerHTML =
                original
            ),
          1500
        );
      }
    );
}

// ============================================================
// DOWNLOAD EXCEL
// ============================================================
function downloadExcel() {
  fetch(
    "/download_excel",
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json"
      },

      body: JSON.stringify({
        table_data:
          window._latestTable ||
          [],

        summary:
          window._latestSummary ||
          "",

        column_label:
          window._columnLabel ||
          "IP"
      })
    }
  )
    .then(
      resp =>
        resp.blob()
    )
    .then(
      blob => {

        const url =
          window.URL.createObjectURL(
            blob
          );

        const a =
          document.createElement(
            "a"
          );

        a.href =
          url;

        a.download =
          "IP_Info.xlsx";

        document.body.appendChild(
          a
        );

        a.click();

        a.remove();

        window.URL.revokeObjectURL(
          url
        );

        const btn =
          document.getElementById(
            "downloadExcelBtn"
          );

        btn.textContent =
          "Downloaded";

        btn.classList.add(
          "downloaded"
        );

        btn.disabled =
          true;

        setTimeout(
          () => {

            btn.innerHTML =
              '<i class="ph ph-download-simple"></i> Export to Excel';

            btn.classList.remove(
              "downloaded"
            );

            btn.disabled =
              false;
          },
          5000
        );
      }
    )
    .catch(
      error => {

        console.error(
          "Download failed:",
          error
        );

        alert(
          "Download failed. Please try again."
        );
      }
    );
}

// ============================================================
// RESET TOOL
// ============================================================
function resetTool() {
  document.getElementById(
    "ipInput"
  ).value = "";

  document.getElementById(
    "message"
  ).innerHTML = "";

  const messageBlock =
    document.getElementById(
      "messageBlock"
    );

  if (
    messageBlock
  ) {

    messageBlock.classList.remove(
      "show"
    );

    messageBlock.classList.add(
      "hidden"
    );

    messageBlock.style.display =
      "none";
  }

  document.getElementById(
    "errorMsg"
  ).classList.add(
    "hidden"
  );

  document.getElementById(
    "summarySection"
  ).classList.add(
    "hidden"
  );

  document.getElementById(
    "tableSection"
  ).classList.add(
    "hidden"
  );

  document.getElementById(
    "summary"
  ).innerHTML =
    "";

  document.getElementById(
    "tableBody"
  ).innerHTML =
    "";

  document.getElementById(
    "downloadExcelBtn"
  ).style.display =
    "none";

  document.getElementById(
    "resetContainer"
  ).classList.add(
    "hidden"
  );
}

// ============================================================
// THEME TOGGLE
// ============================================================
const toggleThemeBtn =
  document.getElementById(
    "toggleTheme"
  );

window.addEventListener(
  "DOMContentLoaded",
  () => {

    styleApiKeyInputs();

    const savedTheme =
      localStorage.getItem(
        "theme"
      );

    if (
      savedTheme === "light"
    ) {

      document.body.classList.add(
        "light-mode"
      );

      if (toggleThemeBtn) {
        toggleThemeBtn.innerHTML =
          '<i class="ph ph-moon"></i>';
      }

    } else {

      document.body.classList.remove(
        "light-mode"
      );

      if (toggleThemeBtn) {
        toggleThemeBtn.innerHTML =
          '<i class="ph ph-sun"></i>';
      }
    }
  }
);

if (toggleThemeBtn) {

  toggleThemeBtn.addEventListener(
    "click",
    () => {

      document.body.classList.toggle(
        "light-mode"
      );

      const isLight =
        document.body.classList.contains(
          "light-mode"
        );

      toggleThemeBtn.innerHTML =
        isLight
          ? '<i class="ph ph-moon"></i>'
          : '<i class="ph ph-sun"></i>';

      localStorage.setItem(
        "theme",
        isLight
          ? "light"
          : "dark"
      );
    }
  );
}
