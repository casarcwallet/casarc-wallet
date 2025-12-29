try {
  importScripts("lib/ethers.min.js");
} catch (e) {}

try {
  importScripts("lib/supabase.bundle.js");
} catch (e) {}

const ARC_RPC = "https://rpc.testnet.arc.network";
const ARC_CHAIN_ID_HEX = "0x4cef52";
const ARC_CHAIN_ID_DEC = 5042002;
const USDC_ADDRESS = "0x3600000000000000000000000000000000000000";
const UNIVERSAL_ROUTER_ADDRESS = "0xbf4479C07Dc6fdc6dAa764A0ccA06969e894275F";
const PERMITTED_ORIGINS_KEY = "casarc_dapp_permissions";

const SUPABASE_URL = "https://nujvyleeibifqtbpeqzn.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im51anZ5bGVlaWJpZnF0YnBlcXpuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjU4NDU4MTAsImV4cCI6MjA4MTQyMTgxMH0.qmv_qTXS3O4eIbyA2rAJL3RMF2QWj-6OxpkXzMh7UOI";

const chromeStorage = {
  getItem: async (key) => {
    try {
      const res = await chrome.storage.local.get([key]);
      const v = res && typeof res[key] !== "undefined" ? res[key] : null;
      return v === null ? null : String(v);
    } catch (e) {
      return null;
    }
  },
  setItem: async (key, value) => {
    try {
      await chrome.storage.local.set({ [key]: String(value) });
    } catch (e) {}
  },
  removeItem: async (key) => {
    try {
      await chrome.storage.local.remove([key]);
    } catch (e) {}
  }
};

let supabaseClient = null;

function isSupabaseClient(obj) {
  return !!(
    obj &&
    typeof obj === "object" &&
    obj.auth &&
    typeof obj.auth.getSession === "function" &&
    typeof obj.auth.signInWithOAuth === "function"
  );
}

function resolveCreateClient() {
  const g = globalThis;

  const candidates = [
    g.supabase,
    g.Supabase,
    g.supabaseJs,
    g.supabasejs,
    g.supabase_lib,
    g.supabaseLib
  ].filter(Boolean);

  for (const c of candidates) {
    if (c && typeof c.createClient === "function") return c.createClient.bind(c);
  }

  for (const k of Object.keys(g)) {
    try {
      const v = g[k];
      if (v && typeof v.createClient === "function") return v.createClient.bind(v);
    } catch (e) {}
  }

  return null;
}

function getSupabase() {
  if (supabaseClient && supabaseClient.auth) return supabaseClient;

  const g = globalThis;

  if (isSupabaseClient(g.supabase)) {
    supabaseClient = g.supabase;
    return supabaseClient;
  }

  const createClient = resolveCreateClient();
  if (!createClient) return null;

  const hasChromeStorage =
    typeof chrome !== "undefined" &&
    chrome.storage &&
    chrome.storage.local &&
    typeof chrome.storage.local.get === "function";

  const storageImpl = hasChromeStorage ? chromeStorage : undefined;

  supabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      flowType: "pkce",
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
      ...(storageImpl ? { storage: storageImpl } : {})
    }
  });

  return supabaseClient;
}

function parseHashParams(urlStr) {
  try {
    const u = new URL(urlStr);
    const hash = u.hash && u.hash.startsWith("#") ? u.hash.slice(1) : "";
    return new URLSearchParams(hash);
  } catch (e) {
    return new URLSearchParams("");
  }
}

function extractOAuthError(urlStr) {
  try {
    const u = new URL(urlStr);

    const qErr = u.searchParams.get("error");
    const qDesc = u.searchParams.get("error_description");
    if (qErr || qDesc) {
      return { error: qErr || null, description: qDesc || null };
    }

    const hp = parseHashParams(urlStr);
    const hErr = hp.get("error");
    const hDesc = hp.get("error_description");
    if (hErr || hDesc) {
      return { error: hErr || null, description: hDesc || null };
    }

    return null;
  } catch (e) {
    return null;
  }
}

function normalizeUserCancelErrorMessage(msg) {
  const m = String(msg || "").toLowerCase();

  if (m.includes("did not approve access")) return "did not approve access";
  if (m.includes("user denied") || m.includes("access_denied")) return "did not approve access";
  if (m.includes("the user denied access")) return "did not approve access";
  if (m.includes("user cancelled") || m.includes("user canceled")) return "did not approve access";
  if (m.includes("user closed") || m.includes("closed the window")) return "did not approve access";
  if (m.includes("cancel")) return "did not approve access";

  return null;
}

async function runLaunchWebAuthFlow(url) {
  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow({ url, interactive: true }, (responseUrl) => {
      const rawErr = chrome.runtime.lastError ? chrome.runtime.lastError.message : null;

      if (rawErr) {
        const normalized = normalizeUserCancelErrorMessage(rawErr);
        if (normalized) return reject(new Error(normalized));
        return reject(new Error(rawErr));
      }

      if (!responseUrl) return reject(new Error("No responseUrl from launchWebAuthFlow"));

      const oe = extractOAuthError(responseUrl);
      if (oe && (oe.error || oe.description)) {
        const normalized = normalizeUserCancelErrorMessage(oe.error || oe.description);
        if (normalized) return reject(new Error(normalized));
        return reject(new Error(oe.description || oe.error || "oauth_error"));
      }

      resolve(responseUrl);
    });
  });
}

async function completeSupabaseSessionFromRedirect(sb, responseUrl) {
  const oe = extractOAuthError(responseUrl);
  if (oe && (oe.error || oe.description)) {
    const normalized = normalizeUserCancelErrorMessage(oe.error || oe.description);
    if (normalized) throw new Error(normalized);
    throw new Error(oe.description || oe.error || "oauth_error");
  }

  const u = new URL(responseUrl);
  const code = u.searchParams.get("code");

  if (code && typeof sb.auth.exchangeCodeForSession === "function") {
    const { error } = await sb.auth.exchangeCodeForSession(code);
    if (error) {
      const normalized = normalizeUserCancelErrorMessage(error.message || error);
      if (normalized) throw new Error(normalized);
      throw error;
    }
    return;
  }

  const hp = parseHashParams(responseUrl);
  const access_token = hp.get("access_token");
  const refresh_token = hp.get("refresh_token");

  if (access_token && refresh_token && typeof sb.auth.setSession === "function") {
    const { error } = await sb.auth.setSession({ access_token, refresh_token });
    if (error) {
      const normalized = normalizeUserCancelErrorMessage(error.message || error);
      if (normalized) throw new Error(normalized);
      throw error;
    }
    return;
  }

  if (typeof sb.auth.getSessionFromUrl === "function") {
    const { error } = await sb.auth.getSessionFromUrl({ storeSession: true });
    if (error) {
      const normalized = normalizeUserCancelErrorMessage(error.message || error);
      if (normalized) throw new Error(normalized);
      throw error;
    }
    return;
  }

  throw new Error("Unable to complete session from redirect URL");
}

function forceOAuthParams(oauthUrl, provider, redirectTo) {
  try {
    const u = new URL(oauthUrl);
    if (provider) u.searchParams.set("provider", provider);
    if (redirectTo) u.searchParams.set("redirect_to", redirectTo);
    return u.toString();
  } catch (e) {
    return oauthUrl;
  }
}

function setQueryParam(urlStr, key, value) {
  try {
    const u = new URL(urlStr);
    if (value === null || typeof value === "undefined") u.searchParams.delete(key);
    else u.searchParams.set(key, value);
    return u.toString();
  } catch (e) {
    return urlStr;
  }
}

function normalizeSupabaseAuthorizeUrl(urlFromSb, provider, redirectTo) {
  let u = forceOAuthParams(urlFromSb, provider, redirectTo);

  const isXProvider = provider === "x" || provider === "twitter";
  if (isXProvider) {
    u = setQueryParam(u, "scopes", "users.read");
    u = setQueryParam(u, "scope", null);
  }

  return u;
}

function getProviderCandidates(providerName) {
  const p = String(providerName || "").toLowerCase().trim();
  if (p === "x" || p === "twitter" || p === "twitter/x" || p === "x/twitter") {
    return ["x", "twitter"];
  }
  if (!p) return ["google"];
  return [p];
}

async function startSupabaseOAuth(providerName) {
  const sb = getSupabase();
  if (!sb || !sb.auth) throw new Error("Supabase client not available in background");

  const raw = String(providerName || "").toLowerCase().trim();
  const normalized = raw === "twitter" ? "x" : raw;

  const redirectTo = chrome.identity.getRedirectURL("supabase-auth");
  const candidates = getProviderCandidates(normalized);

  let lastErr = null;

  for (const provider of candidates) {
    const isXProvider = provider === "x" || provider === "twitter";
    const oauthOptions = {
      redirectTo,
      skipBrowserRedirect: true,
      ...(isXProvider ? { scopes: "tweet.read users.read" } : {})
    };

    const res = await sb.auth.signInWithOAuth({
      provider,
      options: oauthOptions
    });

    if (res.error) {
      lastErr = res.error;
      continue;
    }

    const urlFromSb = res.data && res.data.url ? res.data.url : null;
    if (!urlFromSb) {
      lastErr = new Error("No OAuth URL returned by Supabase");
      continue;
    }

    const launchUrl = normalizeSupabaseAuthorizeUrl(urlFromSb, provider, redirectTo);

    try {
      const responseUrl = await runLaunchWebAuthFlow(launchUrl);
      await completeSupabaseSessionFromRedirect(sb, responseUrl);

      const { data: sdata, error: serr } = await sb.auth.getSession();
      if (serr) throw serr;
      if (!sdata || !sdata.session || !sdata.session.user) {
        throw new Error("Session missing after OAuth");
      }

      const session = sdata.session;

      return {
        userId: session.user.id,
        email: session.user.email || null,
        session: {
          access_token: session.access_token,
          refresh_token: session.refresh_token,
          expires_at: session.expires_at || null
        }
      };
    } catch (e) {
      lastErr = e;

      const msg = e && e.message ? String(e.message) : String(e);
      const normalizedCancel = normalizeUserCancelErrorMessage(msg);
      if (normalizedCancel) {
        throw new Error(normalizedCancel);
      }

      continue;
    }
  }

  throw lastErr || new Error("OAuth failed for all provider candidates");
}

function loadPermittedOrigins() {
  return new Promise((resolve) => {
    chrome.storage.local.get([PERMITTED_ORIGINS_KEY], (res) => {
      const map = res && res[PERMITTED_ORIGINS_KEY];
      if (map && typeof map === "object") resolve(map);
      else resolve({});
    });
  });
}

function savePermittedOrigins(map) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [PERMITTED_ORIGINS_KEY]: map || {} }, () => resolve());
  });
}

function getSenderOrigin(sender) {
  if (sender && sender.origin) return sender.origin;
  if (sender && sender.tab && sender.tab.url) {
    try {
      return new URL(sender.tab.url).origin;
    } catch (e) {}
  }
  return null;
}

let unlockedWallet = null;
let pendingSignRequest = null;
let pendingTxRequest = null;
let pendingConnectRequest = null;
let pendingConnectWindowId = null;

chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.set({ mustLockOnPopupOpen: true });
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ mustLockOnPopupOpen: true });
});

chrome.windows.onRemoved.addListener((windowId) => {
  if (
    pendingConnectRequest &&
    typeof pendingConnectWindowId === "number" &&
    windowId === pendingConnectWindowId
  ) {
    const { rpcSendResponse } = pendingConnectRequest;
    pendingConnectRequest = null;
    pendingConnectWindowId = null;
    try {
      rpcSendResponse({ ok: false, error: "User closed the connection popup" });
    } catch (e) {}
  }
});

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(password, text) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const data = enc.encode(text);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { salt: Array.from(salt), iv: Array.from(iv), cipher: Array.from(new Uint8Array(cipher)) };
}

async function decryptText(password, box) {
  const dec = new TextDecoder();
  const salt = new Uint8Array(box.salt);
  const iv = new Uint8Array(box.iv);
  const cipher = new Uint8Array(box.cipher);
  const key = await deriveKey(password, salt);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return dec.decode(plain);
}

function getVault() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["casarcVault"], (res) => resolve(res.casarcVault || null));
  });
}

function setVault(vault) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ casarcVault: vault }, () => resolve());
  });
}

function clearVaultStorage() {
  return new Promise((resolve) => {
    chrome.storage.local.remove(["casarcVault"], () => resolve());
  });
}

async function callRpc(method, params) {
  const body = { jsonrpc: "2.0", id: Date.now(), method, params };
  const res = await fetch(ARC_RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || "RPC error");
  return json.result;
}

async function getUsdcBalance(address) {
  const iface = new ethers.utils.Interface(["function balanceOf(address) view returns (uint256)"]);
  const data = iface.encodeFunctionData("balanceOf", [address]);
  const raw = await callRpc("eth_call", [{ to: USDC_ADDRESS, data }, "latest"]);
  const bn = ethers.BigNumber.from(raw);
  return ethers.utils.formatUnits(bn, 6);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg && msg.type === "SUPABASE_OAUTH_START") {
        try {
          const provider = msg.provider || "google";
          const result = await startSupabaseOAuth(provider);
          sendResponse({ ok: true, ...result });
        } catch (e) {
          const emsg = e && e.message ? String(e.message) : String(e);
          const normalized = normalizeUserCancelErrorMessage(emsg);
          sendResponse({ ok: false, error: normalized || emsg });
        }
        return;
      }

      if (msg && msg.type === "OAUTH_CALLBACK") {
        sendResponse({ ok: true });
        return;
      }

      if (msg && msg.type === "SUPABASE_AUTH_DONE") {
        sendResponse({ ok: true });
        return;
      }

      if (msg && msg.type === "HAS_VAULT") {
        const vault = await getVault();
        sendResponse({ ok: true, hasVault: !!vault });
        return;
      }

      if (msg && msg.type === "CREATE_VAULT") {
        const { password } = msg;
        const wallet = ethers.Wallet.createRandom();
        const pkBox = await encryptText(password, wallet.privateKey);
        const mnemonicBox = wallet.mnemonic ? await encryptText(password, wallet.mnemonic.phrase) : null;

        await setVault({ pk: pkBox, mnemonic: mnemonicBox });
        unlockedWallet = wallet;

        sendResponse({
          ok: true,
          address: wallet.address,
          mnemonic: wallet.mnemonic ? wallet.mnemonic.phrase : null
        });
        return;
      }

      if (msg && msg.type === "IMPORT_VAULT") {
        const { password, mnemonic } = msg;
        const wallet = ethers.Wallet.fromMnemonic(mnemonic.trim());
        const pkBox = await encryptText(password, wallet.privateKey);
        const mnemonicBox = await encryptText(password, mnemonic.trim());

        await setVault({ pk: pkBox, mnemonic: mnemonicBox });
        unlockedWallet = wallet;

        sendResponse({ ok: true, address: wallet.address });
        return;
      }

      if (msg && msg.type === "UNLOCK_VAULT") {
        const { password } = msg;
        const vault = await getVault();
        if (!vault || !vault.pk) {
          sendResponse({ ok: false, error: "No wallet found" });
          return;
        }
        try {
          const pk = await decryptText(password, vault.pk);
          unlockedWallet = new ethers.Wallet(pk);
          sendResponse({ ok: true, address: unlockedWallet.address });
        } catch (e) {
          sendResponse({ ok: false, error: "Wrong password" });
        }
        return;
      }

      if (msg && msg.type === "SET_ACTIVE_ACCOUNT_SIMPLE") {
        const { privateKey } = msg;
        if (!privateKey) {
          unlockedWallet = null;
          sendResponse({ ok: false, error: "No private key" });
          return;
        }
        try {
          unlockedWallet = new ethers.Wallet(privateKey);
          sendResponse({ ok: true, address: unlockedWallet.address });
        } catch (e) {
          unlockedWallet = null;
          sendResponse({ ok: false, error: "Invalid private key" });
        }
        return;
      }

      if (msg && msg.type === "LOCK") {
        unlockedWallet = null;
        sendResponse({ ok: true });
        return;
      }

      if (msg && msg.type === "DELETE_WALLET") {
        await clearVaultStorage();
        unlockedWallet = null;
        sendResponse({ ok: true });
        return;
      }

      if (msg && msg.type === "GET_ADDRESS") {
        if (unlockedWallet) sendResponse({ ok: true, address: unlockedWallet.address });
        else sendResponse({ ok: false, error: "Locked" });
        return;
      }

      if (msg && msg.type === "GET_SIGN_MESSAGE") {
        const text = pendingSignRequest && pendingSignRequest.message ? pendingSignRequest.message : null;
        sendResponse({ ok: true, message: text });
        return;
      }

      if (msg && msg.type === "GET_TX_REQUEST") {
        if (pendingTxRequest && pendingTxRequest.txReq) {
          const txReq = pendingTxRequest.txReq;
          let gasInfo = null;

          try {
            const from = (unlockedWallet && unlockedWallet.address) || txReq.from || null;

            if (from && txReq.to) {
              const gasPriceHex = await callRpc("eth_gasPrice", []);
              const gasLimitHex = await callRpc("eth_estimateGas", [
                { from, to: txReq.to, data: txReq.data || "0x", value: txReq.value || "0x0" }
              ]);

              const gasPrice = ethers.BigNumber.from(gasPriceHex);
              const gasLimit = ethers.BigNumber.from(gasLimitHex);
              const feeWei = gasPrice.mul(gasLimit);

              gasInfo = { gasPriceHex, gasLimitHex, feeHex: feeWei.toHexString() };
            }
          } catch (e) {}

          sendResponse({ ok: true, tx: txReq, gas: gasInfo });
        } else {
          sendResponse({ ok: false, error: "No pending tx" });
        }
        return;
      }

      if (msg && msg.type === "EXPORT_KEYS") {
        const { password } = msg;
        const vault = await getVault();
        if (!vault || !vault.pk) {
          sendResponse({ ok: false, error: "No wallet" });
          return;
        }
        try {
          const pk = await decryptText(password, vault.pk);
          let mnemonic = null;
          if (vault.mnemonic) mnemonic = await decryptText(password, vault.mnemonic);
          unlockedWallet = new ethers.Wallet(pk);
          sendResponse({ ok: true, privateKey: pk, mnemonic });
        } catch (e) {
          sendResponse({ ok: false, error: "Wrong password" });
        }
        return;
      }

      if (msg && msg.type === "GET_BALANCE") {
        if (!unlockedWallet) {
          sendResponse({ ok: false, error: "Locked" });
          return;
        }
        const addr = unlockedWallet.address;
        const usdc = await getUsdcBalance(addr);
        const nativeHex = await callRpc("eth_getBalance", [addr, "latest"]);
        const native = ethers.utils.formatEther(ethers.BigNumber.from(nativeHex));
        sendResponse({ ok: true, usdc, native });
        return;
      }

      if (msg && msg.type === "SEND_USDC") {
        if (!unlockedWallet) {
          sendResponse({ ok: false, error: "Locked" });
          return;
        }
        const { to, amount } = msg;
        const value = ethers.utils.parseUnits(amount, 6);

        const iface = new ethers.utils.Interface(["function transfer(address to, uint256 amount)"]);
        const data = iface.encodeFunctionData("transfer", [to, value]);

        const from = unlockedWallet.address;
        const nonceHex = await callRpc("eth_getTransactionCount", [from, "latest"]);
        const gasPriceHex = await callRpc("eth_gasPrice", []);
        const gasLimitHex = await callRpc("eth_estimateGas", [{ from, to: USDC_ADDRESS, data }]);

        const tx = {
          chainId: ARC_CHAIN_ID_DEC,
          to: USDC_ADDRESS,
          data,
          nonce: ethers.BigNumber.from(nonceHex).toNumber(),
          gasPrice: ethers.BigNumber.from(gasPriceHex),
          gasLimit: ethers.BigNumber.from(gasLimitHex),
          value: 0
        };

        const signed = await unlockedWallet.signTransaction(tx);
        const hash = await callRpc("eth_sendRawTransaction", [signed]);
        sendResponse({ ok: true, hash });
        return;
      }

      if (msg && msg.type === "UNIVERSAL_ROUTER_SWAP") {
        try {
          if (!unlockedWallet) {
            sendResponse({ ok: false, error: "Locked" });
            return;
          }

          const payload = msg.payload || msg || {};
          const routerAddr = payload.routerAddress || UNIVERSAL_ROUTER_ADDRESS;
          const data = payload.data;

          if (!data || typeof data !== "string" || !data.startsWith("0x")) {
            sendResponse({ ok: false, error: "Swap routing is not configured yet (no router calldata)." });
            return;
          }

          const from = unlockedWallet.address;
          const valueHex = payload.valueHex || "0x0";
          const valueBN = ethers.BigNumber.from(valueHex);

          const nonceHex = await callRpc("eth_getTransactionCount", [from, "latest"]);
          const gasPriceHex = await callRpc("eth_gasPrice", []);
          const gasLimitHex = await callRpc("eth_estimateGas", [
            { from, to: routerAddr, data, value: valueBN.toHexString() }
          ]);

          const tx = {
            chainId: ARC_CHAIN_ID_DEC,
            from,
            to: routerAddr,
            data,
            value: valueBN,
            nonce: ethers.BigNumber.from(nonceHex).toNumber(),
            gasPrice: ethers.BigNumber.from(gasPriceHex),
            gasLimit: ethers.BigNumber.from(gasLimitHex)
          };

          const signed = await unlockedWallet.signTransaction(tx);
          const hash = await callRpc("eth_sendRawTransaction", [signed]);

          sendResponse({ ok: true, hash });
        } catch (e) {
          let msgText = "Swap failed.";
          const m = e && e.message ? String(e.message) : "";

          if (/insufficient funds(?: for gas)?/i.test(m)) {
            msgText = "Not enough native gas balance. Keep a small USDC for fees.";
          } else if (e.code === "CALL_EXCEPTION" || /execution reverted/i.test(m)) {
            msgText = "Swap reverted on-chain (likely missing allowance or pool liquidity).";
          }

          sendResponse({ ok: false, error: msgText });
        }
        return;
      }

      if (msg && msg.type === "SIGN_RESPONSE") {
        if (!pendingSignRequest || !pendingSignRequest.rpcSendResponse) {
          sendResponse({ ok: false, error: "No pending sign request" });
          return;
        }

        const { approved } = msg;
        const { message, rpcSendResponse, method, params } = pendingSignRequest;
        pendingSignRequest = null;

        if (!approved) {
          rpcSendResponse({ ok: false, error: "User rejected the signature" });
          sendResponse({ ok: true });
          return;
        }

        if (!unlockedWallet) {
          rpcSendResponse({ ok: false, error: "Wallet locked" });
          sendResponse({ ok: false, error: "Wallet locked" });
          return;
        }

        try {
          if (!method || method === "personal_sign") {
            const bytes = ethers.utils.isHexString(message)
              ? ethers.utils.arrayify(message)
              : ethers.utils.toUtf8Bytes(message);

            const sig = await unlockedWallet.signMessage(bytes);
            rpcSendResponse({ ok: true, result: sig });
            sendResponse({ ok: true });
            return;
          }

          if (method === "eth_signTypedData_v4") {
            const rawParams = Array.isArray(params) ? params : [];
            const typedDataParam = rawParams[1];

            if (!typedDataParam) {
              rpcSendResponse({ ok: false, error: "Missing typed data" });
              sendResponse({ ok: false, error: "Missing typed data" });
              return;
            }

            let dataObj;
            try {
              dataObj = typeof typedDataParam === "string" ? JSON.parse(typedDataParam) : typedDataParam;
            } catch (e) {
              rpcSendResponse({ ok: false, error: "Invalid typed data JSON" });
              sendResponse({ ok: false, error: "Invalid typed data JSON" });
              return;
            }

            const domain = dataObj.domain || {};
            const types = Object.assign({}, dataObj.types || {});
            delete types.EIP712Domain;
            const value = dataObj.message || {};

            const sig = await unlockedWallet._signTypedData(domain, types, value);
            rpcSendResponse({ ok: true, result: sig });
            sendResponse({ ok: true });
            return;
          }

          const errMsg = "Unsupported sign method: " + method;
          rpcSendResponse({ ok: false, error: errMsg });
          sendResponse({ ok: false, error: errMsg });
        } catch (e) {
          rpcSendResponse({ ok: false, error: e.message || "Sign failed" });
          sendResponse({ ok: false, error: e.message || "Sign failed" });
        }
        return;
      }

      if (msg && msg.type === "TX_RESPONSE") {
        if (!pendingTxRequest || !pendingTxRequest.txReq || !pendingTxRequest.rpcSendResponse) {
          sendResponse({ ok: false, error: "No pending tx" });
          return;
        }

        const { approved } = msg;
        const { txReq, rpcSendResponse } = pendingTxRequest;
        pendingTxRequest = null;

        if (!approved) {
          rpcSendResponse({ ok: false, error: "User rejected the transaction" });
          sendResponse({ ok: true });
          return;
        }

        if (!unlockedWallet) {
          rpcSendResponse({ ok: false, error: "Wallet locked" });
          sendResponse({ ok: false, error: "Wallet locked" });
          return;
        }

        try {
          const from = unlockedWallet.address;
          const nonceHex = await callRpc("eth_getTransactionCount", [from, "latest"]);
          const gasPriceHex = await callRpc("eth_gasPrice", []);
          const gasLimitHex = await callRpc("eth_estimateGas", [
            { from, to: txReq.to, data: txReq.data || "0x", value: txReq.value || "0x0" }
          ]);

          const tx = {
            chainId: ARC_CHAIN_ID_DEC,
            from,
            to: txReq.to,
            data: txReq.data || "0x",
            value: txReq.value ? ethers.BigNumber.from(txReq.value) : ethers.BigNumber.from(0),
            nonce: ethers.BigNumber.from(nonceHex).toNumber(),
            gasPrice: ethers.BigNumber.from(gasPriceHex),
            gasLimit: ethers.BigNumber.from(gasLimitHex)
          };

          const signed = await unlockedWallet.signTransaction(tx);
          const hash = await callRpc("eth_sendRawTransaction", [signed]);

          rpcSendResponse({ ok: true, result: hash });
          sendResponse({ ok: true });
        } catch (e) {
          rpcSendResponse({ ok: false, error: e.message || "Transaction failed" });
          sendResponse({ ok: false, error: e.message || "Transaction failed" });
        }
        return;
      }

      if (msg && msg.type === "GET_CONNECT_REQUEST") {
        const origin = pendingConnectRequest && pendingConnectRequest.origin ? pendingConnectRequest.origin : null;
        sendResponse({ ok: !!origin, origin });
        return;
      }

      if (msg && msg.type === "CONNECT_RESPONSE") {
        const current = pendingConnectRequest;
        pendingConnectRequest = null;
        pendingConnectWindowId = null;

        if (!current || !current.rpcSendResponse) {
          sendResponse({ ok: false, error: "No pending connection request" });
          return;
        }

        const { approved } = msg;
        const { origin, rpcSendResponse } = current;

        if (!approved) {
          rpcSendResponse({ ok: false, error: "User rejected the connection" });
          sendResponse({ ok: true });
          return;
        }

        const permittedMap = await loadPermittedOrigins();
        permittedMap[origin] = true;
        await savePermittedOrigins(permittedMap);

        if (!unlockedWallet) {
          rpcSendResponse({ ok: false, error: "Wallet locked" });
          sendResponse({ ok: false, error: "Wallet locked" });
          return;
        }

        rpcSendResponse({ ok: true, result: [unlockedWallet.address] });
        sendResponse({ ok: true });
        return;
      }

      if (msg && msg.type === "RPC_REQUEST" && msg.fromPage) {
        const { method, params } = msg;

        const origin = getSenderOrigin(sender);
        const permittedMap = await loadPermittedOrigins();
        const isPermitted = origin && permittedMap[origin] === true;

        if (method === "eth_chainId") {
          sendResponse({ ok: true, result: ARC_CHAIN_ID_HEX });
          return;
        }

        if (method === "eth_accounts" || method === "eth_requestAccounts") {
          if (!origin) {
            sendResponse({ ok: true, result: [] });
            return;
          }

          if (method === "eth_accounts") {
            const result = unlockedWallet && isPermitted ? [unlockedWallet.address] : [];
            sendResponse({ ok: true, result });
            return;
          }

          if (isPermitted && unlockedWallet) {
            sendResponse({ ok: true, result: [unlockedWallet.address] });
            return;
          }

          if (pendingConnectRequest) {
            sendResponse({ ok: false, error: "Another connection request is already pending" });
            return;
          }

          pendingConnectRequest = { origin, rpcSendResponse: sendResponse };

          chrome.windows.create(
            { url: "popup.html#connect", type: "popup", width: 420, height: 560, focused: true },
            (win) => {
              if (win && typeof win.id === "number") pendingConnectWindowId = win.id;
            }
          );

          return;
        }

        if (
          (method === "personal_sign" || method === "eth_sendTransaction" || method === "eth_signTypedData_v4") &&
          !isPermitted
        ) {
          sendResponse({
            ok: false,
            error: "This site is not connected to Casarc. Call eth_requestAccounts first."
          });
          return;
        }

        if (method === "personal_sign") {
          if (!unlockedWallet) {
            sendResponse({ ok: false, error: "Wallet locked" });
            return;
          }
          if (pendingSignRequest) {
            sendResponse({ ok: false, error: "Another sign request is already pending" });
            return;
          }

          const rawMessage = Array.isArray(params) ? params[0] : null;
          pendingSignRequest = {
            method: "personal_sign",
            params,
            message: rawMessage,
            rpcSendResponse: sendResponse
          };

          chrome.windows.create({ url: "popup.html#sign", type: "popup", width: 380, height: 420 });
          return;
        }

        if (method === "eth_signTypedData_v4") {
          if (!unlockedWallet) {
            sendResponse({ ok: false, error: "Wallet locked" });
            return;
          }
          if (pendingSignRequest) {
            sendResponse({ ok: false, error: "Another sign request is already pending" });
            return;
          }

          const rawParams = Array.isArray(params) ? params : [];
          const typedDataParam = rawParams[1];

          let preview = "";
          try {
            if (typeof typedDataParam === "string") preview = typedDataParam;
            else if (typedDataParam && typeof typedDataParam === "object")
              preview = JSON.stringify(typedDataParam, null, 2);
            else preview = "Typed data";
          } catch (e) {
            preview = "Typed data";
          }

          if (preview.length > 2000) preview = preview.slice(0, 2000) + "\n...[truncated]";

          pendingSignRequest = {
            method: "eth_signTypedData_v4",
            params: rawParams,
            message: preview,
            rpcSendResponse: sendResponse
          };

          chrome.windows.create({ url: "popup.html#sign", type: "popup", width: 380, height: 420 });
          return;
        }

        if (method === "eth_sendTransaction") {
          if (!unlockedWallet) {
            sendResponse({ ok: false, error: "Wallet locked" });
            return;
          }
          if (pendingTxRequest) {
            sendResponse({ ok: false, error: "Another transaction is already pending confirmation" });
            return;
          }

          const txReq = params && params[0] ? params[0] : {};
          pendingTxRequest = { txReq, rpcSendResponse: sendResponse };

          chrome.windows.create({ url: "popup.html#tx", type: "popup", width: 380, height: 480 });
          return;
        }

        try {
          const result = await callRpc(method, params || []);
          sendResponse({ ok: true, result });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
        return;
      }
    } catch (e) {
      try {
        sendResponse({ ok: false, error: e.message || "Unknown error" });
      } catch (_) {}
    }
  })();

  return true;
});
