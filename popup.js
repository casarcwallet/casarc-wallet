const CONFIG = {
  RPC_URL: "https://rpc.testnet.arc.network",
  USDC_ADDRESS: null,
  EXPLORER_TX: "https://testnet.arcscan.app/tx/",
  CHAIN_ID_DEC: 5042002,
  CHAIN_ID_HEX: "0x4cef52",
  NETWORK_NAME: "ARC Testnet",
  ROUTER_ADDRESS: "0xbf4479C07Dc6fdc6dAa764A0ccA06969e894275F",
  FACTORY_ADDRESS: "0x0fB6EEDA6e90E90797083861A75D15752a27f59c",
  WUSDC_ADDRESS: "0x911b4000D3422F482F4062a913885f7b035382Df",
  PERMIT2_ADDRESS: "0x000000000022d473030f116ddee9f6b43ac78ba3"
};

const NATIVE_USDC_DECIMALS = 18;

const OAUTH_REDIRECT_URL = chrome.identity.getRedirectURL("supabase-auth");

async function startEmailOtp(email) {
  const e = (email || "").trim();
  if (!e) throw new Error("Email missing");
  const res = await window.supabase.auth.signInWithOtp({
    email: e,
    options: { emailRedirectTo: OAUTH_REDIRECT_URL }
  });
  if (res && res.error) throw res.error;
  return true;
}

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
    {
      name: "PBKDF2",
      salt,
      iterations: 150000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(password, data) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const plain = enc.encode(JSON.stringify(data));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plain
  );
  return {
    salt: Array.from(salt),
    iv: Array.from(iv),
    cipher: Array.from(new Uint8Array(cipher))
  };
}

async function decryptVault(password, box) {
  const dec = new TextDecoder();
  const salt = new Uint8Array(box.salt);
  const iv = new Uint8Array(box.iv);
  const cipher = new Uint8Array(box.cipher);
  const key = await deriveKey(password, salt);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipher
  );
  return JSON.parse(dec.decode(plain));
}

const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)"
];

const ROUTER_ABI = [
  "function execute(bytes commands, bytes[] inputs, uint256 deadline) payable"
];

const FACTORY_ABI = [
  "function getPool(address tokenA,address tokenB,uint24 fee) external view returns (address pool)"
];

const POOL_ABI = [
  "function liquidity() external view returns (uint128)",
  "function token0() external view returns (address)",
  "function token1() external view returns (address)",
  "function slot0() external view returns (uint160 sqrtPriceX96,int24,int16,uint16,uint16,uint8,bool)"
];

const poolTokenDecimalsCache = {};

async function getTokenDecimalsForPool(addr, providerForPool) {
  if (!addr) return 18;
  const key = addr.toLowerCase();
  if (poolTokenDecimalsCache[key] != null) {
    return poolTokenDecimalsCache[key];
  }

  try {
    const c = new ethers.Contract(addr, ERC20_ABI, providerForPool);
    const d = await withRetry(() => c.decimals(), { tries: 2, baseDelay: 200 });
    const dec = typeof d === "number" && !isNaN(d) ? d : 18;
    poolTokenDecimalsCache[key] = dec;
    return dec;
  } catch (e) {
    poolTokenDecimalsCache[key] = 18;
    return 18;
  }
}

const V3_FEE_TIERS = [3000, 500, 100, 10000];

async function findPoolWithLiquidity(factory, tokenA, tokenB, providerForPool) {
  let best = null;

  for (const fee of V3_FEE_TIERS) {
    const pool = await withRetry(() => factory.getPool(tokenA, tokenB, fee), {
      tries: 3,
      baseDelay: 300
    });

    if (!pool || pool === ethers.constants.AddressZero) {
      continue;
    }

    try {
      const poolContract = new ethers.Contract(pool, POOL_ABI, providerForPool);
      const liq = await withRetry(() => poolContract.liquidity(), {
        tries: 2,
        baseDelay: 200
      });

      if (liq && !liq.isZero()) {
        best = { pool, fee, liquidity: liq };
        break;
      }
    } catch (e) {}
  }

  return best;
}

async function buildSwapRoute(factory, tokenIn, tokenOut, providerForPool) {
  const inAddr = tokenIn.toLowerCase();
  const outAddr = tokenOut.toLowerCase();
  const hubAddr = (CONFIG.WUSDC_ADDRESS || "").toLowerCase();

  const direct = await findPoolWithLiquidity(
    factory,
    tokenIn,
    tokenOut,
    providerForPool
  );
  if (direct) {
    return {
      type: "direct",
      hops: [{ tokenIn, tokenOut, fee: direct.fee, pool: direct.pool }]
    };
  }

  if (hubAddr && inAddr !== hubAddr && outAddr !== hubAddr) {
    const via1 = await findPoolWithLiquidity(
      factory,
      tokenIn,
      CONFIG.WUSDC_ADDRESS,
      providerForPool
    );
    const via2 = await findPoolWithLiquidity(
      factory,
      CONFIG.WUSDC_ADDRESS,
      tokenOut,
      providerForPool
    );

    if (via1 && via2) {
      return {
        type: "via-hub",
        hops: [
          {
            tokenIn,
            tokenOut: CONFIG.WUSDC_ADDRESS,
            fee: via1.fee,
            pool: via1.pool
          },
          {
            tokenIn: CONFIG.WUSDC_ADDRESS,
            tokenOut,
            fee: via2.fee,
            pool: via2.pool
          }
        ]
      };
    }
  }

  return null;
}

async function estimateOutputForRoute(
  route,
  poolTokenIn,
  poolTokenOut,
  amountInHuman,
  providerForPool
) {
  try {
    if (!route || !route.hops || !route.hops.length) return null;
    if (!poolTokenIn || !poolTokenOut) return null;

    const p = providerForPool;
    let currentToken = poolTokenIn.toLowerCase();
    let amtHuman = Number(amountInHuman);
    if (!isFinite(amtHuman) || amtHuman <= 0) return null;

    for (const hop of route.hops) {
      if (!hop.pool) return null;

      const pool = new ethers.Contract(hop.pool, POOL_ABI, p);

      const [sqrtPriceX96] = await withRetry(() => pool.slot0(), {
        tries: 2,
        baseDelay: 200
      });
      const token0 = (
        await withRetry(() => pool.token0(), { tries: 2, baseDelay: 200 })
      ).toLowerCase();
      const token1 = (
        await withRetry(() => pool.token1(), { tries: 2, baseDelay: 200 })
      ).toLowerCase();

      const dec0 = await getTokenDecimalsForPool(token0, p);
      const dec1 = await getTokenDecimalsForPool(token1, p);

      const sqrtNum = parseFloat(ethers.BigNumber.from(sqrtPriceX96).toString());
      if (!isFinite(sqrtNum) || sqrtNum <= 0) return null;

      const priceRaw = (sqrtNum * sqrtNum) / Math.pow(2, 192);
      const priceHuman1Per0 = priceRaw * Math.pow(10, dec0 - dec1);

      let outHuman;
      let nextToken;

      if (currentToken === token0) {
        outHuman = amtHuman * priceHuman1Per0;
        nextToken = token1;
      } else if (currentToken === token1) {
        const priceHuman0Per1 = 1 / priceHuman1Per0;
        outHuman = amtHuman * priceHuman0Per1;
        nextToken = token0;
      } else {
        return null;
      }

      const feeTier = hop.fee || 0;
      const feeFrac = feeTier / 1e6;
      outHuman = outHuman * (1 - feeFrac);

      amtHuman = outHuman;
      currentToken = nextToken;
    }

    return amtHuman;
  } catch (e) {
    return null;
  }
}

function encodeV3PathFromHops(hops) {
  if (!hops || !hops.length) {
    throw new Error("encodeV3PathFromHops: empty hops");
  }

  const types = ["address"];
  const values = [hops[0].tokenIn];

  for (const hop of hops) {
    types.push("uint24", "address");
    values.push(hop.fee, hop.tokenOut);
  }

  const path = ethers.utils.solidityPack(types, values);
  return path;
}

const STORAGE_KEY = "casarc_vault_v1";
const SESSION_PASS_KEY = "casarc_session_pass";
const HISTORY_KEY = "casarc_history_v1";
const TOKEN_STORAGE_KEY = "casarc_tokens_v2";

const SUPABASE_UID_KEY = "casarc_supabase_uid";

function getSupabaseUid() {
  try {
    return localStorage.getItem(SUPABASE_UID_KEY) || "";
  } catch (e) {
    return "";
  }
}

function setSupabaseUid(uid) {
  try {
    if (uid) localStorage.setItem(SUPABASE_UID_KEY, uid);
    else localStorage.removeItem(SUPABASE_UID_KEY);
  } catch (e) {}
}

function getVaultStorageKey() {
  const uid = getSupabaseUid();
  return uid ? STORAGE_KEY + "_" + uid : STORAGE_KEY;
}

function getUidVaultKey(uid) {
  return uid ? STORAGE_KEY + "_" + uid : STORAGE_KEY;
}

function migrateLegacyVaultToUid(uid) {
  try {
    if (!uid) return;
    const uidKey = getUidVaultKey(uid);
    const hasUid = !!localStorage.getItem(uidKey);
    if (hasUid) return;

    const legacy = localStorage.getItem(STORAGE_KEY);
    if (legacy) {
      localStorage.setItem(uidKey, legacy);
    }
  } catch (e) {}
}

const VAULTS_TABLE = "casarc_vaults";

async function fetchRemoteVault(uid) {
  if (!uid) return null;
  if (!window.supabase || !window.supabase.from) return null;

  const { data, error } = await window.supabase
    .from(VAULTS_TABLE)
    .select("vault")
    .eq("user_id", uid)
    .maybeSingle();

  if (error) throw error;
  return data && data.vault ? data.vault : null;
}

async function ensureRemoteVaultCached(uid) {
  if (!uid) return false;

  const uidKey = getUidVaultKey(uid);
  const local = localStorage.getItem(uidKey);
  if (local) return true;

  const vault = await fetchRemoteVault(uid);
  if (!vault) return false;

  const raw = JSON.stringify(vault);
  localStorage.setItem(uidKey, raw);
  localStorage.setItem(STORAGE_KEY, raw);
  return true;
}

async function upsertRemoteVault(uid, box) {
  if (!uid) return;
  if (!box) return;
  if (!window.supabase || !window.supabase.from) return;

  const payload = {
    user_id: uid,
    vault: box,
    updated_at: new Date().toISOString()
  };

  const { error } = await window.supabase
    .from(VAULTS_TABLE)
    .upsert(payload, { onConflict: "user_id" });

  if (error) throw error;
}

let decryptedVault = null;
let currentPassword = null;

const DEFAULT_TOKENS = [
  {
    id: "usdc",
    symbol: "USDC",
    name: "USD Coin (native)",
    address: null,
    icon: "icons/usdc.png",
    decimals: NATIVE_USDC_DECIMALS
  },
  {
    id: "wusdc",
    symbol: "WUSDC",
    name: "Wrapped USDC",
    address: CONFIG.WUSDC_ADDRESS,
    icon: "icons/usdc.png",
    decimals: 6
  },
  {
    id: "eurc",
    symbol: "EURC",
    name: "Euro Coin",
    address: "0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a",
    icon: null,
    decimals: 6
  },
  {
    id: "usyc",
    symbol: "USYC",
    name: "USYC",
    address: null,
    icon: null,
    decimals: 6
  },
  {
    id: "usdt",
    symbol: "USDT",
    name: "Tether USD",
    address: "0x175CdB1D338945f0D851A741ccF787D343E57952",
    icon: null,
    decimals: 6
  }
];

function isNativeUsdcToken(t) {
  return t && t.symbol === "USDC" && !t.address;
}

let currentAddress = null;
let flow = { mode: null, mnemonic: null, createKind: null };
let provider = null;
let usdc = null;
let usdcDecimals = 6;
let lastUsdc = null;
let pollTimer = null;
let currentPageName = "wallet";

let tokenConfig = null;
let tokenContracts = {};
let tokenBalances = {};
let lastTokenBalances = {};
let currentSendTokenSymbol = "USDC";

let swapFromSymbol = "USDC";
let swapToSymbol = "EURC";

let pendingSwapInfo = null;

let pendingUiSend = null;

let keysDisplayEl = null;
let sensitiveKeysTimer = null;

let keysAutoHideTimer = null;

function hideSensitiveKeys() {
  try {
    if (keysAutoHideTimer) {
      clearTimeout(keysAutoHideTimer);
      keysAutoHideTimer = null;
    }
    const el = document.getElementById("keysDisplay");
    if (el) {
      el.innerHTML = "";
      el.classList.add("hidden");
    }
  } catch (e) {}
}

function armSensitiveAutoHide(ms = 30000) {
  if (keysAutoHideTimer) clearTimeout(keysAutoHideTimer);

  keysAutoHideTimer = setTimeout(() => {
    hideSensitiveKeys();
    showMessage("Seed/private key hidden.");
  }, ms);
}

function loadTokensConfig() {
  if (tokenConfig) return tokenConfig;
  try {
    const raw = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!raw) {
      tokenConfig = DEFAULT_TOKENS.slice();
      return tokenConfig;
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || !parsed.length) {
      tokenConfig = DEFAULT_TOKENS.slice();
      return tokenConfig;
    }

    const bySymbol = {};
    parsed.forEach((t) => {
      if (t && t.symbol) bySymbol[t.symbol] = t;
    });

    DEFAULT_TOKENS.forEach((bt) => {
      if (!bySymbol[bt.symbol]) {
        parsed.unshift(bt);
        bySymbol[bt.symbol] = bt;
      } else {
        const target = bySymbol[bt.symbol];
        target.name = bt.name;
        target.address = bt.address;
        target.icon = bt.icon;
        target.decimals = bt.decimals;
      }
    });

    tokenConfig = parsed;
    return tokenConfig;
  } catch {
    tokenConfig = DEFAULT_TOKENS.slice();
    return tokenConfig;
  }
}

function saveTokensConfig(list) {
  try {
    localStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify(list));
  } catch {}
}

function getTokenBySymbol(symbol) {
  const tokens = loadTokensConfig();
  return tokens.find((t) => t.symbol === symbol);
}

function ensureTokenContracts() {
  if (!provider) return;
  const tokens = loadTokensConfig();
  tokens.forEach((t) => {
    if (t.address && !tokenContracts[t.symbol]) {
      tokenContracts[t.symbol] = new ethers.Contract(
        t.address,
        ERC20_ABI,
        provider
      );
    }
  });
}

function renderTokenList() {
  const list = document.getElementById("tokenList");
  if (!list) return;

  const tokens = loadTokensConfig();
  list.innerHTML = "";

  tokens.forEach((t) => {
    const bal =
      typeof tokenBalances[t.symbol] === "number" ? tokenBalances[t.symbol] : 0;

    const row = document.createElement("div");
    row.className = "token-row";
    row.setAttribute("data-balance", String(bal));
    row.setAttribute("data-symbol", t.symbol);

    const left = document.createElement("div");
    left.className = "token-left";

    const iconWrapper = document.createElement("div");
    iconWrapper.className = "token-icon-wrapper";

    if (t.icon && t.icon !== "null" && t.icon !== "undefined") {
      const img = document.createElement("img");
      img.src = t.icon;
      img.alt = t.symbol;
      img.className = "token-icon";
      iconWrapper.appendChild(img);
    } else {
      const fallback = document.createElement("div");
      fallback.className = "token-fallback-icon";
      const first = (t.symbol || "?").charAt(0).toUpperCase();
      fallback.textContent = first;
      iconWrapper.appendChild(fallback);
    }

    left.appendChild(iconWrapper);

    const textBox = document.createElement("div");
    const nameEl = document.createElement("div");
    nameEl.className = "token-name";
    nameEl.textContent = t.symbol;

    const subEl = document.createElement("div");
    subEl.className = "token-sub";
    subEl.textContent = t.name || "";

    textBox.appendChild(nameEl);
    textBox.appendChild(subEl);

    left.appendChild(textBox);

    const right = document.createElement("div");
    right.className = "token-right";
    right.textContent = bal.toFixed(6);

    row.appendChild(left);
    row.appendChild(right);

    list.appendChild(row);
  });

  applyHideZero();
}

function refreshSendTokenOptions() {
  const sel = document.getElementById("sendTokenSelect");
  if (!sel) return;
  const tokens = loadTokensConfig();
  const prev = sel.value || currentSendTokenSymbol || "USDC";
  sel.innerHTML = "";
  tokens.forEach((t) => {
    const opt = document.createElement("option");
    opt.value = t.symbol;
    opt.textContent = t.symbol;
    sel.appendChild(opt);
  });
  const hasPrev = tokens.some((t) => t.symbol === prev);
  sel.value = hasPrev ? prev : tokens[0]?.symbol || "";
  currentSendTokenSymbol = sel.value;
  updateSendAvailableLabel();
}

function stopBalancePolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function startBalancePolling() {
  stopBalancePolling();
  if (
    provider &&
    currentPageName === "wallet" &&
    document.visibilityState === "visible"
  ) {
    refreshBalances();
    pollTimer = setInterval(refreshBalances, 8000);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function withRetry(fn, { tries = 3, baseDelay = 300 } = {}) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      await sleep(baseDelay * Math.pow(2, i));
    }
  }
  throw lastErr;
}

function getEncryptedVaultBox() {
  try {
    const uid = getSupabaseUid();
    const uidKey = getUidVaultKey(uid);

    let raw = localStorage.getItem(uidKey);

    if (!raw && uid) {
      const legacy = localStorage.getItem(STORAGE_KEY);
      if (legacy) {
        localStorage.setItem(uidKey, legacy);
        raw = legacy;
      }
    }

    if (!raw && !uid) {
      raw = localStorage.getItem(STORAGE_KEY);
    }

    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function setEncryptedVaultBox(box) {
  try {
    const uid = getSupabaseUid();
    const key = getUidVaultKey(uid);

    if (!box) {
      localStorage.removeItem(key);
      if (uid) localStorage.removeItem(STORAGE_KEY);
    } else {
      const raw = JSON.stringify(box);
      localStorage.setItem(key, raw);
      if (uid) localStorage.setItem(STORAGE_KEY, raw);

      if (uid) {
        upsertRemoteVault(uid, box).catch(() => {});
      }
    }
  } catch {}
}

function loadVault() {
  return decryptedVault;
}

async function createInitialVaultFromWallet(
  password,
  walletAddress,
  mnemonicOrNull,
  privateKeyOrNull
) {
  const vault = {
    selectedAccountIndex: 0,
    accounts: [
      {
        id: "acc-1",
        label: "Account 1",
        type: mnemonicOrNull ? "mnemonic" : "privateKey",
        address: walletAddress,
        mnemonic: mnemonicOrNull,
        privateKey: privateKeyOrNull,
        path: mnemonicOrNull ? "m/44'/60'/0'/0/0" : null,
        index: mnemonicOrNull ? 0 : null
      }
    ]
  };

  const box = await encryptVault(password, vault);
  setEncryptedVaultBox(box);
  decryptedVault = vault;
  currentPassword = password;
  return vault;
}

async function unlockExistingVault(password) {
  const box = getEncryptedVaultBox();
  if (!box) return null;

  const v = await decryptVault(password, box);

  if (v && v.locked) {
    v.locked = false;
    try {
      const newBox = await encryptVault(password, v);
      setEncryptedVaultBox(newBox);
    } catch (e) {}
  }

  decryptedVault = v;
  currentPassword = password;
  return v;
}

async function saveVault(v) {
  if (!currentPassword || !v) return false;
  try {
    const box = await encryptVault(currentPassword, v);
    setEncryptedVaultBox(box);
    decryptedVault = v;
    return true;
  } catch {
    return false;
  }
}

function clearVault() {
  decryptedVault = null;
  currentPassword = null;
  clearSessionPassword();
  try {
    const uid = getSupabaseUid();
    localStorage.removeItem(getUidVaultKey(uid));
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
}

function rememberSessionPassword(pass) {
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.session) {
      const obj = {};
      obj[SESSION_PASS_KEY] = pass;
      const res = chrome.storage.session.set(obj);
      if (res && typeof res.catch === "function") res.catch(() => {});
    }
  } catch (e) {}
}

function clearSessionPassword() {
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.session) {
      const res = chrome.storage.session.remove(SESSION_PASS_KEY);
      if (res && typeof res.catch === "function") res.catch(() => {});
    }
  } catch (e) {}
}

function getActiveAccount(v) {
  if (!v || !Array.isArray(v.accounts) || !v.accounts.length) return null;
  let idx =
    typeof v.selectedAccountIndex === "number" ? v.selectedAccountIndex : 0;
  if (idx < 0 || idx >= v.accounts.length) idx = 0;
  return v.accounts[idx];
}

function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!currentAddress) {
      if (Array.isArray(parsed)) return parsed;
      return [];
    }
    const addr = currentAddress.toLowerCase();
    if (Array.isArray(parsed)) {
      const map = { [addr]: parsed };
      localStorage.setItem(HISTORY_KEY, JSON.stringify(map));
      return parsed;
    }
    if (parsed && typeof parsed === "object") {
      const recs = parsed[addr] || [];
      return Array.isArray(recs) ? recs : [];
    }
    return [];
  } catch {
    return [];
  }
}

function saveHistory(a) {
  try {
    if (!currentAddress) return;
    const addr = currentAddress.toLowerCase();
    const raw = localStorage.getItem(HISTORY_KEY);
    let all;
    try {
      all = raw ? JSON.parse(raw) : {};
    } catch {
      all = {};
    }
    if (!all || typeof all !== "object") all = {};
    all[addr] = a;
    localStorage.setItem(HISTORY_KEY, JSON.stringify(all));
  } catch {}
}

function pushHistory(e) {
  const a = loadHistory();
  a.unshift(e);
  saveHistory(a);
  renderHistory();
}

function shortAddr(a) {
  return a ? a.slice(0, 6) + "..." + a.slice(-4) : "";
}

function showScreen(id) {
  document
    .querySelectorAll(".screen")
    .forEach((s) => s.classList.toggle("hidden", s.id !== id));
}

function updateCreateMethodButtons() {
  const seedBtn = document.getElementById("btnContinueSeed");
  if (!seedBtn) return;

  seedBtn.style.display = "";
  if (flow && flow.mode === "create") {
    seedBtn.textContent = "Create with secret recovery phrase";
  } else {
    seedBtn.textContent = "Use secret recovery phrase";
  }
}

function showMessage(t) {
  const b = document.getElementById("messageBar");
  if (!b) return;
  b.textContent = t;
  b.classList.remove("hidden");
  b.classList.add("visible");
  setTimeout(() => b.classList.remove("visible"), 1400);
}

async function bootstrapSupabaseSessionAndUid() {
  try {
    if (!window.supabase || !window.supabase.auth) return { uid: "", hasSession: false };

    const res = await window.supabase.auth.getSession();
    const sess = res && res.data && res.data.session ? res.data.session : null;

    if (sess && sess.user && typeof sess.user.id === "string" && sess.user.id) {
      const uid = sess.user.id;
      setSupabaseUid(uid);
      migrateLegacyVaultToUid(uid);
      await ensureRemoteVaultCached(uid);
      return { uid, hasSession: true };
    }
  } catch (e) {}
  return { uid: "", hasSession: false };
}

async function routeAfterSupabaseAuth() {
  try {
    let uid = getSupabaseUid();

    if (!uid) {
      try {
        if (window.supabase && window.supabase.auth && window.supabase.auth.getSession) {
          const res = await window.supabase.auth.getSession();
          const sess = res && res.data && res.data.session ? res.data.session : null;
          if (sess && sess.user && typeof sess.user.id === "string" && sess.user.id) {
            uid = sess.user.id;
            setSupabaseUid(uid);
            migrateLegacyVaultToUid(uid);
          }
        }
      } catch (e) {}
    }

    if (uid) {
      await ensureRemoteVaultCached(uid);
    }

    const boxNow = getEncryptedVaultBox();

    if (!boxNow) {
      flow.mode = "create";
      flow.createKind = "social";
      showScreen("screen-create");
      showMessage("Signed in. Set a wallet password to finish.");
    } else {
      showScreen("screen-lock");
      showMessage("Signed in. Unlock your wallet.");
    }
  } catch (e) {
    showScreen("screen-lock");
  }
}

function openInlinePrompt({
  title,
  message,
  placeholder = "",
  isPassword = false
} = {}) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("appDialogOverlay");
    const titleEl = document.getElementById("appDialogTitle");
    const msgEl = document.getElementById("appDialogMessage");
    const input = document.getElementById("appDialogInput");
    const btnOk = document.getElementById("appDialogOk");
    const btnCancel = document.getElementById("appDialogCancel");

    if (!overlay || !titleEl || !msgEl || !input || !btnOk || !btnCancel) {
      const res = window.prompt(message || title || "");
      resolve(res === null ? null : res);
      return;
    }

    titleEl.textContent = title || "";
    msgEl.textContent = message || "";
    input.value = "";
    input.placeholder = placeholder || "";
    input.type = isPassword ? "password" : "text";
    input.style.display = "block";

    btnOk.textContent = "OK";
    btnCancel.textContent = "Cancel";

    function cleanup(result) {
      overlay.classList.add("hidden");
      btnOk.removeEventListener("click", onOk);
      btnCancel.removeEventListener("click", onCancel);
      input.removeEventListener("keydown", onKey);
      resolve(result);
    }

    function onOk() {
      cleanup(input.value.trim());
    }

    function onCancel() {
      cleanup(null);
    }

    function onKey(e) {
      if (e.key === "Enter") onOk();
      if (e.key === "Escape") onCancel();
    }

    btnOk.addEventListener("click", onOk);
    btnCancel.addEventListener("click", onCancel);
    input.addEventListener("keydown", onKey);

    overlay.classList.remove("hidden");
    input.focus();
  });
}

function openInlineConfirm({
  title,
  message,
  okText = "OK",
  cancelText = "Cancel"
} = {}) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("appDialogOverlay");
    const titleEl = document.getElementById("appDialogTitle");
    const msgEl = document.getElementById("appDialogMessage");
    const input = document.getElementById("appDialogInput");
    const btnOk = document.getElementById("appDialogOk");
    const btnCancel = document.getElementById("appDialogCancel");

    if (!overlay || !titleEl || !msgEl || !input || !btnOk || !btnCancel) {
      const res = window.confirm(message || title || "");
      resolve(!!res);
      return;
    }

    titleEl.textContent = title || "";
    msgEl.textContent = message || "";
    input.value = "";
    input.style.display = "none";

    btnOk.textContent = okText || "OK";
    btnCancel.textContent = cancelText || "Cancel";

    function cleanup(result) {
      overlay.classList.add("hidden");
      btnOk.removeEventListener("click", onOk);
      btnCancel.removeEventListener("click", onCancel);
      resolve(result);
    }

    function onOk() {
      cleanup(true);
    }

    function onCancel() {
      cleanup(false);
    }

    btnOk.addEventListener("click", onOk);
    btnCancel.addEventListener("click", onCancel);

    overlay.classList.remove("hidden");
  });
}

async function startOAuth(oauthProvider) {
  try {
    const requested = (oauthProvider || "").toLowerCase().trim();

    const tryProviders =
      requested === "x" || requested === "twitter"
        ? ["x"]
        : [requested || "google"];

    showMessage("Opening sign-in...");

    let res = null;
    let lastErr = null;

    for (const p of tryProviders) {
      res = await new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: "SUPABASE_OAUTH_START", provider: p },
          (r) => resolve(r)
        );
      });

      if (res && res.ok) {
        break;
      } else {
        lastErr = (res && res.error) || "unknown_error";

        const m = String(lastErr || "").toLowerCase();
        const isUserCancel =
          m.includes("did not approve access") ||
          m.includes("access_denied") ||
          m.includes("user closed") ||
          m.includes("cancel") ||
          m.includes("unable to complete session from redirect url");

        if (!isUserCancel) {
          void 0;
        }

        res = null;
      }
    }

    if (!res || !res.ok) {
      const msg = String(lastErr || "");
      const m = msg.toLowerCase();

      if (
        m.includes("did not approve access") ||
        m.includes("user closed") ||
        m.includes("cancel")
      ) {
        return;
      }

      showMessage("Sign-in failed.");
      return;
    }

    if (
      res.session &&
      res.session.access_token &&
      res.session.refresh_token &&
      window.supabase &&
      window.supabase.auth &&
      typeof window.supabase.auth.setSession === "function"
    ) {
      const { error: sessErr } = await window.supabase.auth.setSession({
        access_token: res.session.access_token,
        refresh_token: res.session.refresh_token
      });

      if (sessErr) {
        void 0;
      }
    }

    let uid =
      (typeof res.userId === "string" && res.userId) ||
      (res.user && typeof res.user.id === "string" && res.user.id) ||
      (res.session &&
        res.session.user &&
        typeof res.session.user.id === "string" &&
        res.session.user.id) ||
      "";

    if (!uid) {
      try {
        if (window.supabase?.auth?.getSession) {
          const s = await window.supabase.auth.getSession();
          const sess = s?.data?.session || null;
          if (sess?.user?.id) uid = sess.user.id;
        }
      } catch (e) {}
    }

    if (uid) {
      setSupabaseUid(uid);
      migrateLegacyVaultToUid(uid);
      await ensureRemoteVaultCached(uid).catch(() => {});
    }

    await routeAfterSupabaseAuth();
    showMessage("Signed in. Continue.");
  } catch (e) {
    showMessage("OAuth start failed.");
  }
}

function setNavActive(p) {
  document
    .querySelectorAll(".nav-btn")
    .forEach((b) => b.classList.toggle("active", b.dataset.page === p));
}

function showAppPage(p) {
  currentPageName = p;

  if (p !== "settings") {
    hideSensitiveKeys();
  }

  const hdr = document.getElementById("walletHeader");
  const pages = {
    wallet: document.getElementById("page-wallet"),
    history: document.getElementById("page-history"),
    settings: document.getElementById("page-settings")
  };
  Object.values(pages).forEach((x) => x.classList.add("hidden"));
  hdr.style.display = p === "settings" ? "none" : "block";
  pages[p].classList.remove("hidden");
  setNavActive(p);
  showScreen("screen-app");
  if (p === "wallet") startBalancePolling();
  else stopBalancePolling();
}

function applyHideZero() {
  const chk = document.getElementById("chkHideZero");
  document.querySelectorAll(".token-row").forEach((row) => {
    const bal = parseFloat(row.getAttribute("data-balance") || "0");
    if (chk && chk.checked && bal === 0) row.classList.add("hidden-zero");
    else row.classList.remove("hidden-zero");
  });
}

function setNetworkBadge(text, isError) {
  const titleEl = document.querySelector(".wallet-header-title");
  if (!titleEl) return;
  let badge = titleEl.querySelector(".net-badge");
  if (!badge) {
    badge = document.createElement("span");
    badge.className = "net-badge";
    badge.style.marginLeft = "6px";
    badge.style.fontSize = "10px";
    badge.style.padding = "2px 6px";
    badge.style.borderRadius = "999px";
    titleEl.appendChild(badge);
  }
  badge.textContent = text;
  badge.style.background = isError ? "#5b0f0f" : "#04162a";
  badge.style.color = isError ? "#ff9b9b" : "#17f2e0";
}

function updateSendAvailableLabel() {
  const amt = document.getElementById("sendAmount");
  const sel = document.getElementById("sendTokenSelect");
  if (!amt) return;
  let info = document.getElementById("sendAvailInfo");
  if (!info) {
    info = document.createElement("div");
    info.id = "sendAvailInfo";
    info.style.textAlign = "right";
    info.style.fontSize = "10px";
    info.style.marginTop = "4px";
    info.style.opacity = "0.8";
    amt.insertAdjacentElement("afterend", info);
  }
  const symbol = sel
    ? sel.value || currentSendTokenSymbol || "USDC"
    : currentSendTokenSymbol || "USDC";
  const bal = typeof tokenBalances[symbol] === "number" ? tokenBalances[symbol] : 0;
  info.textContent = "Available: " + bal.toFixed(6) + " " + symbol;
}

function refreshSwapTokenOptions() {
  const fromSel = document.getElementById("swapFromTokenSelect");
  const toSel = document.getElementById("swapToTokenSelect");
  if (!fromSel || !toSel) return;

  const tokens = loadTokensConfig().filter((t) => isNativeUsdcToken(t) || !!t.address);

  const prevFrom = fromSel.value || swapFromSymbol || "USDC";
  const prevTo = toSel.value || swapToSymbol || "EURC";

  fromSel.innerHTML = "";
  toSel.innerHTML = "";

  tokens.forEach((t) => {
    const opt1 = document.createElement("option");
    opt1.value = t.symbol;
    opt1.textContent = t.symbol;
    fromSel.appendChild(opt1);

    const opt2 = document.createElement("option");
    opt2.value = t.symbol;
    opt2.textContent = t.symbol;
    toSel.appendChild(opt2);
  });

  const hasPrevFrom = tokens.some((t) => t.symbol === prevFrom);
  const hasPrevTo = tokens.some((t) => t.symbol === prevTo);

  fromSel.value = hasPrevFrom ? prevFrom : tokens[0]?.symbol || "";
  toSel.value =
    hasPrevTo && prevTo !== fromSel.value
      ? prevTo
      : tokens.find((t) => t.symbol !== fromSel.value)?.symbol ||
        tokens[0]?.symbol ||
        "";

  swapFromSymbol = fromSel.value;
  swapToSymbol = toSel.value;

  updateSwapAvailableLabel();
}

function updateSwapAvailableLabel() {
  const fromSel = document.getElementById("swapFromTokenSelect");
  if (!fromSel) return;

  let info = document.getElementById("swapAvailInfo");
  if (!info) {
    const amtInput = document.getElementById("swapAmount");
    if (!amtInput) return;
    info = document.createElement("div");
    info.id = "swapAvailInfo";
    info.style.textAlign = "right";
    info.style.fontSize = "10px";
    info.style.marginTop = "4px";
    info.style.opacity = "0.8";
    amtInput.insertAdjacentElement("afterend", info);
  }

  const symbol = fromSel.value || swapFromSymbol || "USDC";
  const bal = typeof tokenBalances[symbol] === "number" ? tokenBalances[symbol] : 0;
  info.textContent = "Available: " + bal.toFixed(6) + " " + symbol;
}

function openFaucetForCurrentAddress() {
  const v = loadVault();
  const acc = getActiveAccount(v);
  if (!acc || !acc.address) {
    showMessage("No wallet address.");
    return;
  }
  navigator.clipboard.writeText(acc.address).then(
    () => showMessage("Address copied. Faucet opened in new tab."),
    () => showMessage("Faucet opened. Copy your address from wallet.")
  );
  const faucetUrl = "https://faucet.circle.com/";
  try {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: faucetUrl });
    } else if (
      typeof browser !== "undefined" &&
      browser.tabs &&
      browser.tabs.create
    ) {
      browser.tabs.create({ url: faucetUrl });
    } else {
      window.open(faucetUrl, "_blank");
    }
  } catch (e) {
    window.open(faucetUrl, "_blank");
  }
}

function renderAccountUi() {
  const hdr = document.getElementById("walletHeader");
  if (!hdr) return;
  let bar = document.getElementById("accountBar");
  if (!bar) {
    bar = document.createElement("div");
    bar.id = "accountBar";
    bar.style.marginTop = "8px";
    bar.style.display = "flex";
    bar.style.gap = "6px";
    bar.style.alignItems = "center";
    hdr.appendChild(bar);
  }
  bar.innerHTML = "";
  const v = loadVault();
  if (!v || !Array.isArray(v.accounts) || !v.accounts.length) return;
  const select = document.createElement("select");
  select.id = "accountSelect";
  select.style.flex = "1";
  select.style.fontSize = "11px";
  select.style.padding = "4px 6px";
  select.style.borderRadius = "999px";
  select.style.border = "none";
  v.accounts.forEach((acc, idx) => {
    const opt = document.createElement("option");
    opt.value = String(idx);
    opt.textContent =
      (acc.label || "Account " + (idx + 1)) +
      " (" +
      shortAddr(acc.address) +
      ")";
    if (idx === v.selectedAccountIndex) opt.selected = true;
    select.appendChild(opt);
  });
  select.addEventListener("change", async (e) => {
    const idx = parseInt(e.target.value, 10);
    const v2 = loadVault();
    if (!v2) return;
    if (idx >= 0 && idx < v2.accounts.length) {
      v2.selectedAccountIndex = idx;
      await saveVault(v2);
      openApp();
    }
  });
  bar.appendChild(select);
  const addBtn = document.createElement("button");
  addBtn.id = "btnAddAccountSimple";
  addBtn.className = "btn tiny";
  addBtn.textContent = "+";
  addBtn.style.flex = "0 0 auto";
  addBtn.addEventListener("click", () => {
    createAdditionalAccountFromActive();
  });
  bar.appendChild(addBtn);
  const importBtn = document.createElement("button");
  importBtn.id = "btnImportPkSimple";
  importBtn.className = "btn tiny";
  importBtn.textContent = "⇪";
  importBtn.style.flex = "0 0 auto";
  importBtn.addEventListener("click", () => {
    importAccountViaPrompt();
  });
  bar.appendChild(importBtn);
}

async function createAdditionalAccountFromActive() {
  const v = loadVault();
  if (!v) {
    showMessage("No wallet.");
    return;
  }
  const baseAcc = getActiveAccount(v);
  if (!baseAcc || !baseAcc.mnemonic) {
    showMessage("Active account has no seed.");
    return;
  }

  const pass = await openInlinePrompt({
    title: "Wallet password",
    message: "Enter your wallet password:",
    isPassword: true
  });
  if (pass === null) return;
  if (!currentPassword || pass !== currentPassword) {
    showMessage("Wrong password.");
    return;
  }

  let maxIndex = 0;
  v.accounts.forEach(a => {
    if (typeof a.index === "number" && a.mnemonic === baseAcc.mnemonic && a.index > maxIndex) maxIndex = a.index;
  });
  const newIndex = maxIndex + 1;
  const hd = ethers.utils.HDNode.fromMnemonic(baseAcc.mnemonic);
  const path = "m/44'/60'/0'/0/" + newIndex;
  const child = hd.derivePath(path);
  const address = child.address;
  if (v.accounts.some(a => a.address.toLowerCase() === address.toLowerCase())) {
    showMessage("Account already exists.");
    return;
  }
  const newAcc = {
    id: "acc-" + Date.now(),
    label: "Account " + (v.accounts.length + 1),
    type: "mnemonic",
    address: address,
    mnemonic: baseAcc.mnemonic,
    privateKey: null,
    path: path,
    index: newIndex
  };
  v.accounts.push(newAcc);
  v.selectedAccountIndex = v.accounts.length - 1;
  await saveVault(v);
  openApp();
  showMessage("New account created.");
}

async function importAccountViaPrompt() {
  const v = loadVault();
  if (!v) {
    showMessage("No wallet.");
    return;
  }
  const pass = await openInlinePrompt({
    title: "Wallet password",
    message: "Enter your wallet password:",
    isPassword: true
  });
  if (pass === null) return;
  if (!currentPassword || pass !== currentPassword) {
    showMessage("Wrong password.");
    return;
  }
  const pkRaw = await openInlinePrompt({
    title: "Import account",
    message: "Enter private key (0x...):",
    placeholder: "0x..."
  });
  if (!pkRaw) return;
  let pk = pkRaw.trim();
  if (!pk) return;
  if (!pk.startsWith("0x")) pk = "0x" + pk;
  let wallet;
  try {
    wallet = new ethers.Wallet(pk);
  } catch (e) {
    showMessage("Invalid private key.");
    return;
  }
  if (
    v.accounts.some((a) => a.address.toLowerCase() === wallet.address.toLowerCase())
  ) {
    showMessage("Account already exists.");
    return;
  }
  const newAcc = {
    id: "acc-" + Date.now(),
    label: "Imported " + shortAddr(wallet.address),
    type: "privateKey",
    address: wallet.address,
    mnemonic: null,
    privateKey: pk,
    path: null,
    index: null
  };
  v.accounts.push(newAcc);
  v.selectedAccountIndex = v.accounts.length - 1;
  await saveVault(v);
  openApp();
  showMessage("Account imported.");
}

async function importWalletByMnemonic() {
  const v = loadVault();
  if (!v) {
    showMessage("No wallet.");
    return;
  }
  const pass = await openInlinePrompt({
    title: "Wallet password",
    message: "Enter your wallet password:",
    isPassword: true
  });
  if (pass === null) return;
  if (!currentPassword || pass !== currentPassword) {
    showMessage("Wrong password.");
    return;
  }
  const phraseRaw = await openInlinePrompt({
    title: "Import wallet",
    message: "Enter seed phrase to import (12+ words):",
    placeholder: "seed phrase"
  });
  if (!phraseRaw) return;
  const phrase = phraseRaw.trim();
  if (!phrase || phrase.split(/\s+/).length < 12) {
    showMessage("Enter a valid seed phrase.");
    return;
  }
  let hd;
  try {
    hd = ethers.utils.HDNode.fromMnemonic(phrase);
  } catch (e) {
    showMessage("Invalid seed phrase.");
    return;
  }
  const path = "m/44'/60'/0'/0/0";
  const child = hd.derivePath(path);
  const address = child.address;
  const v2 = loadVault() || v;
  if (
    v2.accounts.some((a) => a.address.toLowerCase() === address.toLowerCase())
  ) {
    showMessage("Account already exists.");
    return;
  }
  const newAcc = {
    id: "acc-" + Date.now(),
    label: "Imported " + shortAddr(address),
    type: "mnemonic",
    address,
    mnemonic: phrase,
    privateKey: null,
    path,
    index: 0
  };
  v2.accounts.push(newAcc);
  v2.selectedAccountIndex = v2.accounts.length - 1;
  await saveVault(v2);
  openApp();
  showMessage("Wallet imported with seed.");
}

function renderAccountsList(filterText) {
  const list = document.getElementById("accountsList");
  if (!list) return;
  const v = loadVault();
  list.innerHTML = "";
  if (!v || !Array.isArray(v.accounts) || !v.accounts.length) {
    list.innerHTML = '<div class="account-empty">No accounts yet.</div>';
    return;
  }
  const term = (filterText || "").toLowerCase();
  v.accounts.forEach((acc, idx) => {
    const label = acc.label || "Account " + (idx + 1);
    const addr = acc.address || "";
    if (
      term &&
      !label.toLowerCase().includes(term) &&
      !addr.toLowerCase().includes(term)
    ) {
      return;
    }
    const item = document.createElement("div");
    item.className = "account-item";
    item.setAttribute("data-index", String(idx));
    if (idx === v.selectedAccountIndex) {
      item.classList.add("active");
    }

    const main = document.createElement("div");
    main.className = "acc-main";
    const lbl = document.createElement("div");
    lbl.className = "acc-label";
    lbl.textContent = label;
    const addrEl = document.createElement("div");
    addrEl.className = "acc-address";
    addrEl.textContent = shortAddr(addr);
    main.appendChild(lbl);
    main.appendChild(addrEl);

    const right = document.createElement("div");
    right.className = "account-item-right";

    if (idx === v.selectedAccountIndex) {
      const badge = document.createElement("span");
      badge.className = "acc-badge";
      badge.textContent = "Active";
      right.appendChild(badge);
    }

    const renameBtn = document.createElement("button");
    renameBtn.className = "acc-rename-btn";
    renameBtn.setAttribute("data-index", String(idx));
    renameBtn.textContent = "✎";
    right.appendChild(renameBtn);

    item.appendChild(main);
    item.appendChild(right);
    list.appendChild(item);
  });

  if (!list.innerHTML) {
    list.innerHTML = '<div class="account-empty">No results found.</div>';
  }
}

async function handleRenameAccount(index) {
  const v = loadVault();
  if (!v || !Array.isArray(v.accounts) || index < 0 || index >= v.accounts.length) return;
  const acc = v.accounts[index];
  const currentName = acc.label || "Account " + (index + 1);
  const newNameRaw = await openInlinePrompt({
    title: "Rename account",
    message: "New account name:",
    placeholder: currentName
  });
  if (!newNameRaw) return;
  const newName = newNameRaw.trim();
  if (!newName) return;
  acc.label = newName;
  await saveVault(v);
  const searchEl = document.getElementById("accountSearch");
  const term = searchEl ? searchEl.value.trim().toLowerCase() : "";
  renderAccountsList(term);
  openApp();
}

function syncActiveAccountToBackground() {
  const v = loadVault();
  const acc = getActiveAccount(v);
  if (!v || !acc) return;

  let pk = null;
  if (acc.mnemonic) {
    try {
      const hd = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
      const path = acc.path || "m/44'/60'/0'/0/0";
      const child = hd.derivePath(path);
      pk = child.privateKey;
    } catch (e) {
      return;
    }
  } else if (acc.privateKey) {
    pk = acc.privateKey;
  }

  if (!pk) return;

  try {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: "SET_ACTIVE_ACCOUNT_SIMPLE",
        address: acc.address,
        privateKey: pk
      });
    }
  } catch (e) {}
}

function openApp() {
  const v = loadVault();
  if (!v || !Array.isArray(v.accounts) || !v.accounts.length) {
    showScreen("screen-init");
    return;
  }

  const acc = getActiveAccount(v);
  if (!acc) {
    showScreen("screen-init");
    return;
  }

  if (currentAddress !== acc.address) {
    lastUsdc = null;
    lastTokenBalances = {};
  }
  currentAddress = acc.address;

  const addrEl = document.getElementById("walletAddressDisplay");
  if (addrEl) addrEl.textContent = shortAddr(acc.address);

  const totalUsdEl = document.getElementById("walletTotalUsd");
  if (totalUsdEl) totalUsdEl.textContent = "$0.00";

  const usdcLabelEl = document.getElementById("walletUsdcLabel");
  if (usdcLabelEl) usdcLabelEl.textContent = "0.000000 USDC";

  const activeNameEl = document.getElementById("activeAccountName");
  const idx = typeof v.selectedAccountIndex === "number" ? v.selectedAccountIndex : 0;
  if (activeNameEl) {
    activeNameEl.textContent = acc.label || "Account " + (idx + 1);
  }

  renderTokenList();
  applyHideZero();
  showAppPage("wallet");
  initProviderIfConfigured();
  refreshBalances();
  renderHistory();
  startBalancePolling();

  syncActiveAccountToBackground();
  renderAccountUi();
}

function lockWallet() {
  hideSensitiveKeys();
  const box = getEncryptedVaultBox();
  if (!box) {
    showScreen("screen-init");
    return;
  }

  decryptedVault = null;
  currentPassword = null;
  clearSessionPassword();

  const up = document.getElementById("unlockPassword");
  if (up) up.value = "";

  showScreen("screen-lock");
  stopBalancePolling();

  try {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: "LOCK" });
    }
  } catch (e) {}
}

async function checkChainIdAndBadge() {
  try {
    const net = await withRetry(() => provider.getNetwork(), { tries: 3, baseDelay: 300 });
    if (Number(net.chainId) !== Number(CONFIG.CHAIN_ID_DEC)) {
      setNetworkBadge("RPC CHAIN MISMATCH", true);
      showMessage("Warning: RPC chainId mismatch.");
    } else {
      setNetworkBadge(CONFIG.NETWORK_NAME, false);
    }
  } catch (e) {
    setNetworkBadge("RPC ERROR", true);
    showMessage("RPC error. Retrying...");
  }
}

function initProviderIfConfigured() {
  if (CONFIG.RPC_URL) {
    provider = new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);
    usdc = CONFIG.USDC_ADDRESS ? new ethers.Contract(CONFIG.USDC_ADDRESS, ERC20_ABI, provider) : null;
    ensureTokenContracts();
    checkChainIdAndBadge();
  } else {
    provider = null;
    usdc = null;
    tokenContracts = {};
    setNetworkBadge("No RPC", true);
  }
}

async function refreshBalances() {
  try {
    if (!provider || !currentAddress) return;
    const tokens = loadTokensConfig();
    if (!tokens.length) return;

    ensureTokenContracts();

    let mutatedTokens = false;
    let usdcBal = 0;
    let totalUsd = 0;

    for (const t of tokens) {
      let bal = 0;
      let dec = typeof t.decimals === "number" ? t.decimals : NATIVE_USDC_DECIMALS;

      if (isNativeUsdcToken(t)) {
        const raw = await withRetry(() => provider.getBalance(currentAddress), {
          tries: 3,
          baseDelay: 300
        });
        bal = Number(ethers.utils.formatUnits(raw, dec));
      } else if (t.address) {
        let c = tokenContracts[t.symbol];
        if (!c) {
          c = new ethers.Contract(t.address, ERC20_ABI, provider);
          tokenContracts[t.symbol] = c;
        }

        try {
          const fetchedDec = await withRetry(() => c.decimals(), { tries: 2, baseDelay: 200 });
          if (typeof fetchedDec === "number" && !isNaN(fetchedDec) && fetchedDec !== dec) {
            dec = fetchedDec;
            t.decimals = dec;
            mutatedTokens = true;
          }
        } catch {}

        const raw = await withRetry(() => c.balanceOf(currentAddress), {
          tries: 3,
          baseDelay: 300
        });
        bal = Number(ethers.utils.formatUnits(raw, dec));
      }

      tokenBalances[t.symbol] = bal;

      const row = document.querySelector('.token-row[data-symbol="' + t.symbol + '"]');
      if (row) {
        row.setAttribute("data-balance", String(bal));
        const right = row.querySelector(".token-right");
        if (right) right.textContent = bal.toFixed(6);
      }

      const prev = lastTokenBalances[t.symbol];
      if (typeof prev === "number" && bal > prev + 1e-12) {
        pushHistory({
          time: Date.now(),
          type: "receive",
          token: t.symbol,
          amount: (bal - prev).toFixed(6),
          from: "(unknown)",
          to: currentAddress,
          txHash: null
        });
      }
      lastTokenBalances[t.symbol] = bal;

      if (t.symbol === "USDC") {
        usdcBal = bal;
      }

      const sym = (t.symbol || "").toUpperCase();
      let priceUsd = 0;
      if (sym === "USDC" || sym === "EURC" || sym === "USYC" || sym === "WUSDC" || sym === "USDT") {
        priceUsd = 1;
      }
      totalUsd += bal * priceUsd;
    }

    if (mutatedTokens) {
      saveTokensConfig(tokens);
      tokenConfig = tokens;
    }

    lastUsdc = usdcBal;

    const usdcLabelEl = document.getElementById("walletUsdcLabel");
    if (usdcLabelEl) {
      usdcLabelEl.textContent = usdcBal.toFixed(6) + " USDC";
    }

    const totalUsdEl = document.getElementById("walletTotalUsd");
    if (totalUsdEl) {
      totalUsdEl.textContent = "$" + totalUsd.toFixed(2);
    }

    applyHideZero();
    updateSendAvailableLabel();
    updateSwapAvailableLabel();
  } catch (e) {
    showMessage("Balance update failed. Retrying...");
  }
}

function formatUtcDateTime(ts) {
  const d = new Date(ts);
  return (
    d.toLocaleString("en-GB", {
      timeZone: "UTC",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }) + " UTC"
  );
}

function renderHistory() {
  const list = document.querySelector("#page-history .history-list");
  if (!list) return;

  const recs = loadHistory();

  if (!recs.length) {
    list.innerHTML =
      '<div class="history-item">' +
      '<div class="history-label">No local activity yet</div>' +
      '<div class="history-time">Your on-chain transaction history will appear here once available.</div>' +
      "</div>";
    return;
  }

  list.innerHTML = "";

  recs.forEach((r) => {
    const when = formatUtcDateTime(r.time);

    const link =
      r.txHash && CONFIG.EXPLORER_TX
        ? `<a class="hist-link" href="${CONFIG.EXPLORER_TX}${r.txHash}" target="_blank" title="Open in explorer">[tx]</a>`
        : "";

    const html = `
      <div class="history-item">
        <div class="history-label">
          ${r.type.toUpperCase()} ${r.amount} ${r.token} ${link}
        </div>
        <div class="history-time">
          ${when} - ${shortAddr(r.from)} -> ${shortAddr(r.to)}
        </div>
      </div>
    `;

    list.insertAdjacentHTML("beforeend", html);
  });
}

async function ensureSwapApprovalIfNeeded(tokenAddress, owner, spender, amountBN, signer) {
  const c = new ethers.Contract(tokenAddress, ERC20_ABI, signer);
  const allowance = await withRetry(() => c.allowance(owner, spender), { tries: 2, baseDelay: 250 });
  if (allowance && allowance.gte(amountBN)) return true;

  const ok = await openInlineConfirm({
    title: "Token approval",
    message: "This swap needs token approval. Approve now?",
    okText: "Approve",
    cancelText: "Cancel"
  });
  if (!ok) return false;

  const max = ethers.constants.MaxUint256;
  const tx = await withRetry(() => c.approve(spender, max), { tries: 2, baseDelay: 300 });
  await withRetry(() => tx.wait(), { tries: 2, baseDelay: 800 });
  return true;
}

async function getActiveSigner(p) {
  const v = loadVault();
  const acc = getActiveAccount(v);
  if (!v || !acc) return null;

  if (acc.mnemonic) {
    const hd = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
    const path = acc.path || "m/44'/60'/0'/0/0";
    const child = hd.derivePath(path);
    return new ethers.Wallet(child.privateKey, p);
  }
  if (acc.privateKey) {
    return new ethers.Wallet(acc.privateKey, p);
  }
  return null;
}

document.addEventListener("DOMContentLoaded", async () => {
  showScreen("screen-loading");

  if (location.hash === "#sign") {
    const screen = document.getElementById("screen-sign");
    const msgBox = document.getElementById("signMessage");
    const btnApprove = document.getElementById("btnSignApprove");
    const btnReject = document.getElementById("btnSignReject");

    if (screen && msgBox && btnApprove && btnReject) {
      showScreen("screen-sign");

      let currentMessage = "";

      chrome.runtime.sendMessage({ type: "GET_SIGN_MESSAGE" }, (res) => {
        if (res && res.message) {
          currentMessage = res.message;
          msgBox.textContent = res.message;
        } else {
          msgBox.textContent = "Mesaj alınamadı.";
        }
      });

      btnReject.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "SIGN_RESPONSE", approved: false });
        window.close();
      });

      btnApprove.addEventListener("click", () => {
        chrome.runtime.sendMessage({
          type: "SIGN_RESPONSE",
          approved: true,
          message: currentMessage
        });
        window.close();
      });
    }

    return;
  }

  if (location.hash === "#tx") {
    const screen = document.getElementById("screen-tx");
    const summaryEl = document.getElementById("txSummary");
    const btnApprove = document.getElementById("btnTxApprove");
    const btnReject = document.getElementById("btnTxReject");
    const btnBack = document.querySelector("#screen-tx .btn.back");

    if (screen && summaryEl && btnApprove && btnReject) {
      showScreen("screen-tx");

      chrome.runtime.sendMessage({ type: "GET_TX_REQUEST" }, async (res) => {
        if (res && res.ok && res.tx) {
          const tx = res.tx;
          const from = tx.from || "(unknown from)";
          const to = tx.to || "(unknown to)";
          const valueHex = tx.value || "0x0";

          let valueText;
          try {
            const bn = ethers.BigNumber.from(valueHex || "0x0");
            valueText = ethers.utils.formatUnits(bn, NATIVE_USDC_DECIMALS) + " USDC";
          } catch (e) {
            valueText = valueHex;
          }

          let typeText = "";
          let feeText = "";

          try {
            const provider = new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);

            let isContract = false;
            if (to && to !== "0x0000000000000000000000000000000000000000") {
              const code = await provider.getCode(to);
              isContract = !!code && code !== "0x";
            }
            typeText = isContract ? "Type: Contract interaction" : "Type: Simple transfer";

            const gasPrice = await provider.getGasPrice();
            const gasLimit = await provider.estimateGas({
              from,
              to: tx.to,
              data: tx.data || "0x",
              value: valueHex || "0x0"
            });
            const fee = gasPrice.mul(gasLimit);
            const feeUsdc = ethers.utils.formatUnits(fee, NATIVE_USDC_DECIMALS);
            feeText = "Estimated fee: " + feeUsdc + " USDC";
          } catch (e) {
            if (!typeText) {
              typeText = "Type: Unknown";
            }
            feeText = "Estimated fee: (could not estimate)";
          }

          let html =
            "From: " +
            from +
            "<br>" +
            "To: " +
            to +
            "<br>";
          if (typeText) {
            html += typeText + "<br>";
          }
          html += "Value: " + valueText + "<br>" + feeText;

          summaryEl.innerHTML = html;
        } else {
          summaryEl.textContent = "No pending transaction.";
        }
      });

      const doReject = () => {
        chrome.runtime.sendMessage({ type: "TX_RESPONSE", approved: false }, () => {
          window.close();
        });
      };

      btnReject.addEventListener("click", doReject);
      if (btnBack) {
        btnBack.addEventListener("click", doReject);
      }

      btnApprove.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "TX_RESPONSE", approved: true }, () => {
          window.close();
        });
      });
    }

    return;
  }

  if (location.hash === "#connect") {
    const screen = document.getElementById("screen-connect");
    const originEl = document.getElementById("connectDappOrigin");
    const btnAllow = document.getElementById("btnConnectApprove");
    const btnCancel = document.getElementById("btnConnectReject");

    if (screen && originEl && btnAllow && btnCancel) {
      showScreen("screen-connect");

      let connectHandled = false;

      function finishConnect(approved) {
        if (connectHandled) return;
        connectHandled = true;

        try {
          chrome.runtime.sendMessage({ type: "CONNECT_RESPONSE", approved }, () => {
            try {
              window.close();
            } catch (e) {}
          });
        } catch (e) {}
      }

      (async () => {
        try {
          const box = getEncryptedVaultBox();
          if (!box) {
            return;
          }

          let sessionPassword = null;
          try {
            if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.session) {
              const res = await chrome.storage.session.get([SESSION_PASS_KEY]);
              if (res && typeof res[SESSION_PASS_KEY] === "string" && res[SESSION_PASS_KEY]) {
                sessionPassword = res[SESSION_PASS_KEY];
              }
            }
          } catch (e) {}

          if (sessionPassword) {
            const v = await unlockExistingVault(sessionPassword);
            if (v && Array.isArray(v.accounts) && v.accounts.length) {
              syncActiveAccountToBackground();
            }
          }
        } catch (e) {}
      })();

      chrome.runtime.sendMessage({ type: "GET_CONNECT_REQUEST" }, (res) => {
        if (res && res.ok && res.origin) {
          originEl.textContent = res.origin;
        } else {
          originEl.textContent = "(no site)";
        }
      });

      btnAllow.addEventListener("click", () => {
        finishConnect(true);
      });

      btnCancel.addEventListener("click", () => {
        finishConnect(false);
      });

      window.addEventListener("beforeunload", () => {
        if (!connectHandled) {
          try {
            chrome.runtime.sendMessage({ type: "CONNECT_RESPONSE", approved: false });
          } catch (e) {}
        }
      });
    } else {
      showScreen("screen-app");
    }

    return;
  }

  try {
    await bootstrapSupabaseSessionAndUid();
  } catch (e) {}

  const box = getEncryptedVaultBox();

  let sessionPassword = null;
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.session) {
      const res = await chrome.storage.session.get([SESSION_PASS_KEY]);
      if (res && typeof res[SESSION_PASS_KEY] === "string" && res[SESSION_PASS_KEY]) {
        sessionPassword = res[SESSION_PASS_KEY];
      }
    }
  } catch (e) {}

  if (!box) {
    showScreen("screen-init");
  } else if (sessionPassword) {
    try {
      const v = await unlockExistingVault(sessionPassword);
      if (v && Array.isArray(v.accounts) && v.accounts.length) {
        openApp();
      } else {
        showScreen("screen-lock");
      }
    } catch (e) {
      clearSessionPassword();
      showScreen("screen-lock");
    }
  } else {
    showScreen("screen-lock");
  }

  const btnCreate = document.getElementById("btnCreate");
  const btnImport = document.getElementById("btnImport");
  const btnContinueGoogle = document.getElementById("btnContinueGoogle");
  const btnContinueEmail = document.getElementById("btnContinueEmail");
  const btnContinueX = document.getElementById("btnContinueX");
  const btnContinueSeed = document.getElementById("btnContinueSeed");
  const btnCreateMethodBack = document.getElementById("btnCreateMethodBack");
  const pw1 = document.getElementById("pw1");
  const pw2 = document.getElementById("pw2");
  const btnSetPassword = document.getElementById("btnSetPassword");
  const mnemonicInput = document.getElementById("mnemonicInput");
  const btnImportNext = document.getElementById("btnImportNext");
  const mnemonicBox = document.getElementById("mnemonicBox");
  const btnCopyMnemonic = document.getElementById("btnCopyMnemonic");
  const btnDoneMnemonic = document.getElementById("btnDoneMnemonic");
  const unlockPassword = document.getElementById("unlockPassword");
  const btnUnlock = document.getElementById("btnUnlock");
  const walletCopyIcon = document.getElementById("walletCopyIcon");
  const walletAddressDisplay = document.getElementById("walletAddressDisplay");
  const btnHeaderLock = document.getElementById("btnHeaderLock");
  const btnSecurity = document.getElementById("btnSecurity");
  const btnAppearance = document.getElementById("btnAppearance");
  const btnShowKeys = document.getElementById("btnShowKeys");
  const btnLock = document.getElementById("btnLock");
  const btnDelete = document.getElementById("btnDelete");
  const btnThemeDark = document.getElementById("btnThemeDark");
  const btnThemeLight = document.getElementById("btnThemeLight");
  const securitySection = document.getElementById("securitySection");
  const appearanceSection = document.getElementById("appearanceSection");
  const keysDisplay = document.getElementById("keysDisplay");
  keysDisplayEl = keysDisplay;

function openAccountsScreen() {
  const v = loadVault();
  if (!v || !Array.isArray(v.accounts) || !v.accounts.length) {
    showMessage("No wallet.");
    return;
  }
  const search = document.getElementById("accountSearch");
  if (search) search.value = "";
  renderAccountsList("");
  showScreen("screen-accounts");
}

const activeNameEl2 = document.getElementById("activeAccountName");
if (activeNameEl2) {
  activeNameEl2.style.cursor = "pointer";
  activeNameEl2.addEventListener("click", openAccountsScreen);
}

  try {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg && msg.type === "SUPABASE_AUTH_DONE") {
        routeAfterSupabaseAuth();
      }
    });
  } catch (e) {}

  const btnOpenSend = document.getElementById("btnOpenSend");
  const btnOpenReceive = document.getElementById("btnOpenReceive");
  const btnSendNow = document.getElementById("btnSendNow");
  const sendTo = document.getElementById("sendTo");
  const sendAmount = document.getElementById("sendAmount");
  const sendTokenSelect = document.getElementById("sendTokenSelect");
  const receiveAddress = document.getElementById("receiveAddress");
  const btnCopyReceive = document.getElementById("btnCopyReceive");
  const chkHideZero = document.getElementById("chkHideZero");
  const btnFaucet = document.getElementById("btnFaucet");
  const btnImportToken = document.getElementById("btnImportToken");

const btnOpenAccounts = document.getElementById("btnOpenAccounts");
const btnCloseAccounts = document.getElementById("btnCloseAccounts");
const accountsListEl = document.getElementById("accountsList");
const accountSearch = document.getElementById("accountSearch");
const btnAddAccount = document.getElementById("btnAddAccount");
const addAccountMenu = document.getElementById("addAccountMenu");

const btnCreateNewAccount = document.getElementById("btnCreateNewAccount");
const btnAddByMnemonic = document.getElementById("btnAddByMnemonic");
const btnAddByPrivateKey = document.getElementById("btnAddByPrivateKey");

function openAccountsScreen() {
  const v = loadVault();
  if (!v || !Array.isArray(v.accounts) || !v.accounts.length) {
    showMessage("No wallet.");
    return;
  }

  stopBalancePolling();

  if (accountSearch) accountSearch.value = "";
  if (addAccountMenu) addAccountMenu.classList.add("hidden");
  renderAccountsList("");
  showScreen("screen-accounts");
}

if (btnOpenAccounts) {
  btnOpenAccounts.addEventListener("click", openAccountsScreen);
}

if (btnCloseAccounts) {
  btnCloseAccounts.addEventListener("click", () => {
    showScreen("screen-app");
    showAppPage("wallet");
    startBalancePolling();
  });
}

if (btnAddAccount && addAccountMenu) {
  btnAddAccount.addEventListener("click", () => {
    addAccountMenu.classList.toggle("hidden");
  });
}

if (btnCreateNewAccount) {
  btnCreateNewAccount.addEventListener("click", async () => {
    if (addAccountMenu) addAccountMenu.classList.add("hidden");
    await createAdditionalAccountFromActive();
    const term = accountSearch ? accountSearch.value.trim().toLowerCase() : "";
    renderAccountsList(term);
  });
}

if (btnAddByMnemonic) {
  btnAddByMnemonic.addEventListener("click", async () => {
    if (addAccountMenu) addAccountMenu.classList.add("hidden");
    await importWalletByMnemonic();
    const term = accountSearch ? accountSearch.value.trim().toLowerCase() : "";
    renderAccountsList(term);
  });
}

if (btnAddByPrivateKey) {
  btnAddByPrivateKey.addEventListener("click", async () => {
    if (addAccountMenu) addAccountMenu.classList.add("hidden");
    await importAccountViaPrompt();
    const term = accountSearch ? accountSearch.value.trim().toLowerCase() : "";
    renderAccountsList(term);
  });
}

if (accountsListEl) {
  accountsListEl.addEventListener("click", (e) => {
    const renameBtn = e.target.closest(".acc-rename-btn");
    if (renameBtn) {
      const idx = parseInt(renameBtn.getAttribute("data-index"), 10);
      if (!isNaN(idx)) handleRenameAccount(idx);
      return;
    }

    const item = e.target.closest(".account-item");
    if (!item) return;

    const idx = parseInt(item.getAttribute("data-index"), 10);
    const v = loadVault();
    if (!v || !Array.isArray(v.accounts) || idx < 0 || idx >= v.accounts.length) return;

    v.selectedAccountIndex = idx;
    saveVault(v).then(() => {
      showScreen("screen-app");
      openApp();
    });
  });
}

if (accountSearch) {
  accountSearch.addEventListener("input", () => {
    const term = accountSearch.value.trim().toLowerCase();
    renderAccountsList(term);
  });
}

  const btnOpenSwap = document.getElementById("btnOpenSwap");
  const btnSwapReview = document.getElementById("btnSwapReview");
  const swapFromSelect = document.getElementById("swapFromTokenSelect");
  const swapToSelect = document.getElementById("swapToTokenSelect");
  const swapAmountIn = document.getElementById("swapAmount");
  const swapSlippage = document.getElementById("swapSlippage");
  const swapAddressDisplay = document.getElementById("swapAddressDisplay");

  const swapReviewFrom = document.getElementById("swapReviewFrom");
  const swapReviewTo = document.getElementById("swapReviewTo");
  const swapReviewNetwork = document.getElementById("swapReviewNetwork");
  const swapReviewFee = document.getElementById("swapReviewFee");
  const btnSwapConfirm = document.getElementById("btnSwapConfirm");
  const btnSwapReviewBack = document.getElementById("btnSwapReviewBack");
  const btnSwapCancel = document.getElementById("btnSwapCancel");

  async function updateSwapReviewFeePreview() {
    if (!swapReviewFee) return;

    try {
      const v = loadVault();
      const acc = getActiveAccount(v);
      if (!v || !acc || !acc.address) {
        swapReviewFee.textContent = "Unknown (no wallet)";
        return;
      }

      if (!CONFIG.RPC_URL) {
        swapReviewFee.textContent = "Unknown (no RPC)";
        return;
      }

      const p = provider || new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);
      if (!provider) provider = p;

      const gasPrice = await withRetry(() => p.getGasPrice(), {
        tries: 3,
        baseDelay: 200
      });

      const GAS_LIMIT_APPROX = ethers.BigNumber.from("250000");
      const feeWei = gasPrice.mul(GAS_LIMIT_APPROX);
      const feeUsdc = ethers.utils.formatEther(feeWei);

      swapReviewFee.textContent = feeUsdc + " USDC";
    } catch (e) {
      swapReviewFee.textContent = "Unknown";
    }
  }

  const btnSendConfirm = document.getElementById("btnSendConfirm");
  const btnSendReject = document.getElementById("btnSendReject");

  loadTokensConfig();
  renderTokenList();
  refreshSendTokenOptions();
  refreshSwapTokenOptions();

  document.querySelectorAll(".btn.back").forEach((b) => {
    b.addEventListener("click", () => {
      const t = b.getAttribute("data-back");
      if (t === "app") {
        showAppPage("wallet");
      } else if (t === "send") {
        showScreen("screen-send");
      } else if (t === "swap") {
        showScreen("screen-swap");
      } else {
        showScreen("screen-init");
      }
    });
  });

  if (btnCreate) {
    btnCreate.addEventListener("click", async () => {
      const uid = getSupabaseUid();
      if (uid) {
        await ensureRemoteVaultCached(uid);
      }

      const existing = getEncryptedVaultBox();
      if (existing) {
        showScreen("screen-lock");
        showMessage("Wallet already exists for this Google account. Unlock it or delete it to create a new one.");
        return;
      }

      flow.mode = "create";
      showScreen("screen-create-method");
      updateCreateMethodButtons();
    });
   }

  if (btnSetPassword) {
    btnSetPassword.addEventListener("click", async () => {
      const p1 = pw1.value.trim();
      const p2 = pw2.value.trim();
      if (p1.length < 8 || p1 !== p2) {
        showMessage("Passwords must match and be at least 8 characters.");
        return;
      }

      try {
        if (flow.mode === "create") {
          const w = ethers.Wallet.createRandom();
          flow.mnemonic = w.mnemonic.phrase;

          if (flow.createKind === "seed") {
            mnemonicBox.textContent = flow.mnemonic;
            showScreen("screen-show-seed");
          } else {
            await createInitialVaultFromWallet(p1, w.address, flow.mnemonic, null);
            rememberSessionPassword(p1);
            openApp();
          }
        } else if (flow.mode === "import") {
          if (!flow.mnemonic) {
            showMessage("Seed phrase missing.");
            return;
          }
          const w = ethers.Wallet.fromMnemonic(flow.mnemonic);
          await createInitialVaultFromWallet(p1, w.address, flow.mnemonic, null);
          rememberSessionPassword(p1);
          openApp();
        } else {
          showMessage("Unknown flow.");
          return;
        }
      } catch {
        showMessage("Error creating wallet.");
      }
    });
  }

  if (btnImport) {
    btnImport.addEventListener("click", () => {
      flow.mode = "login";
      showScreen("screen-create-method");
      updateCreateMethodButtons();
    });
  }

  if (btnCreateMethodBack) {
    btnCreateMethodBack.addEventListener("click", () => {
      showScreen("screen-init");
    });
  }

  if (btnContinueSeed) {
    btnContinueSeed.addEventListener("click", () => {
      if (flow && flow.mode === "create") {
        flow.createKind = "seed";
        if (pw1) pw1.value = "";
        if (pw2) pw2.value = "";
        showScreen("screen-create");
        return;
      }

      flow.mode = "import";
      const mi = document.getElementById("mnemonicInput");
      if (mi) mi.value = "";
      showScreen("screen-import");
    });
  }

  if (btnContinueGoogle) {
    btnContinueGoogle.addEventListener("click", async () => {
      await startOAuth("google");
    });
  }

  if (btnContinueX) {
    btnContinueX.addEventListener("click", () => {
      showMessage("X sign-in is not available yet. Coming soon.");
    });
  }

  if (btnContinueEmail) {
    btnContinueEmail.addEventListener("click", async () => {
      try {
        const email = await openInlinePrompt({
          title: "Continue with Email",
          message: "Enter your email address:",
          placeholder: "you@example.com"
        });
        if (!email) return;
        await startEmailOtp(email);
        showMessage("Check your email for the sign-in link.");
      } catch (e) {
        showMessage("Email sign-in failed.");
      }
    });
  }

  if (btnImportNext) {
    btnImportNext.addEventListener("click", () => {
      const phrase = (mnemonicInput.value || "").trim();
      if (!phrase || phrase.split(" ").length < 12) {
        showMessage("Enter a valid seed phrase.");
        return;
      }
      flow.mnemonic = phrase;
      pw1.value = "";
      pw2.value = "";
      showScreen("screen-create");
    });
  }

  if (btnCopyMnemonic) {
    btnCopyMnemonic.addEventListener("click", () => {
      if (!flow.mnemonic) return;
      navigator.clipboard.writeText(flow.mnemonic).then(() => showMessage("Seed phrase copied."));
    });
  }

  if (btnDoneMnemonic) {
    btnDoneMnemonic.addEventListener("click", async () => {
      const password = pw1.value.trim();
      if (!flow.mnemonic || !password) {
        showMessage("Missing data.");
        return;
      }
      try {
        const w = ethers.Wallet.fromMnemonic(flow.mnemonic);
        await createInitialVaultFromWallet(password, w.address, flow.mnemonic, null);
        rememberSessionPassword(password);
        openApp();
      } catch {
        showMessage("Failed to save wallet.");
      }
    });
  }

  if (btnUnlock) {
    btnUnlock.addEventListener("click", async () => {
      const box = getEncryptedVaultBox();
      if (!box) {
        showMessage("No wallet found.");
        showScreen("screen-init");
        return;
      }

      const pass = (unlockPassword.value || "").trim();
      if (!pass) {
        showMessage("Enter password.");
        return;
      }

      try {
        const v = await unlockExistingVault(pass);
        if (!v || !Array.isArray(v.accounts) || !v.accounts.length) {
          showMessage("Invalid wallet data.");
          return;
        }
        rememberSessionPassword(pass);
        openApp();
      } catch (e) {
        showMessage("Wrong password.");
      }
    });
  }

  document.querySelectorAll(".nav-btn").forEach((btn) =>
    btn.addEventListener("click", () => showAppPage(btn.dataset.page))
  );

  function copyFull() {
    const v = loadVault();
    const acc = getActiveAccount(v);
    if (!acc || !acc.address) return;
    navigator.clipboard.writeText(acc.address).then(() => showMessage("Address copied."));
  }
  if (walletCopyIcon) walletCopyIcon.addEventListener("click", copyFull);
  if (walletAddressDisplay) walletAddressDisplay.addEventListener("click", copyFull);

  if (chkHideZero) {
    chkHideZero.addEventListener("change", applyHideZero);
    applyHideZero();
  }

  if (btnSecurity) {
    btnSecurity.addEventListener("click", () => {
      const isOpenNow = !securitySection.classList.contains("hidden");
      if (isOpenNow) {
        hideSensitiveKeys();
      }
      securitySection.classList.toggle("hidden");
    });
  }

  if (btnAppearance) {
    btnAppearance.addEventListener("click", () => appearanceSection.classList.toggle("hidden"));
  }

  if (btnThemeDark) {
    btnThemeDark.addEventListener("click", () => {
      document.body.classList.remove("light");
      showMessage("Dark theme enabled.");
    });
  }

  if (btnThemeLight) {
    btnThemeLight.addEventListener("click", () => {
      document.body.classList.add("light");
      showMessage("Light theme enabled.");
    });
  }

  if (btnShowKeys) {
    btnShowKeys.addEventListener("click", async () => {
      hideSensitiveKeys();
      const v = loadVault();
      const acc = getActiveAccount(v);
      if (!v || !acc) {
        showMessage("No wallet data.");
        return;
      }
      const pass = await openInlinePrompt({
        title: "Wallet password",
        message: "Enter your wallet password:",
        isPassword: true
      });
      if (pass === null) return;
      if (!currentPassword || pass !== currentPassword) {
        showMessage("Wrong password.");
        return;
      }
      let html = "";
      if (acc.mnemonic) {
        html +=
          '<div class="key-line"><div class="key-label">Seed phrase</div><button class="key-copy" data-type="seed">Copy</button></div>' +
          '<div class="key-value" id="seedValue">' +
          acc.mnemonic +
          "</div>";
      }
      let pk = "";
      if (acc.mnemonic) {
        const hd = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
        const path = acc.path || "m/44'/60'/0'/0/0";
        const child = hd.derivePath(path);
        pk = child.privateKey;
      } else if (acc.privateKey) {
        pk = acc.privateKey;
      }
      if (pk) {
        html +=
          '<div class="key-line"><div class="key-label">Private key</div><button class="key-copy" data-type="pk">Copy</button></div>' +
          '<div class="key-value" id="pkValue">' +
          pk +
          "</div>";
      }
      keysDisplay.innerHTML = html;
      keysDisplay.classList.remove("hidden");
      armSensitiveAutoHide(30000);
    });
  }

  const kd = document.getElementById("keysDisplay");
  if (kd) {
    kd.addEventListener("click", (e) => {
      if (!e.target.classList.contains("key-copy")) return;
      const type = e.target.getAttribute("data-type");
      const el =
        type === "seed"
          ? document.getElementById("seedValue")
          : document.getElementById("pkValue");
      if (!el) return;
      const text = el.textContent;
      navigator.clipboard.writeText(text).then(() =>
        showMessage(type === "seed" ? "Seed phrase copied." : "Private key copied.")
      );
    });
  }

  if (btnLock) btnLock.addEventListener("click", lockWallet);
  if (btnHeaderLock) btnHeaderLock.addEventListener("click", lockWallet);

  if (btnDelete) {
    btnDelete.addEventListener("click", async () => {
      const v = loadVault();
      if (!v || !Array.isArray(v.accounts) || !v.accounts.length) {
        showMessage("No wallet to delete.");
        return;
      }

      const confirmed = await openInlineConfirm({
        title: "Delete wallet",
        message: "Delete wallet from this browser?\nMake sure your seed phrase is backed up.",
        okText: "Delete",
        cancelText: "Cancel"
      });
      if (!confirmed) return;

      const pass = await openInlinePrompt({
        title: "Confirm deletion",
        message: "Enter your wallet password to confirm:",
        isPassword: true
      });
      if (pass === null) return;
      if (!currentPassword || pass !== currentPassword) {
        showMessage("Wrong password.");
        return;
      }
      clearVault();

      try {
        for (let i = localStorage.length - 1; i >= 0; i--) {
          const k = localStorage.key(i);
          if (!k) continue;
          if (k === STORAGE_KEY || k.startsWith(STORAGE_KEY + "_")) {
            localStorage.removeItem(k);
          }
        }
      } catch (e) {}

      try {
        setSupabaseUid("");
      } catch (e) {}

      try {
        if (window.supabase && window.supabase.auth && window.supabase.auth.signOut) {
          await window.supabase.auth.signOut();
        }
      } catch (e) {}

      currentAddress = null;
      lastUsdc = null;
      lastTokenBalances = {};
      tokenBalances = {};
      showScreen("screen-init");
      showMessage("Wallet deleted.");
      stopBalancePolling();

      try {
        if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: "DELETE_WALLET" });
        }
      } catch (e) {}
    });
  }

  if (btnOpenSend) {
    btnOpenSend.addEventListener("click", () => {
      sendTo.value = "";
      sendAmount.value = "";
      refreshSendTokenOptions();
      showScreen("screen-send");
      updateSendAvailableLabel();
    });
  }

  if (sendTokenSelect) {
    sendTokenSelect.addEventListener("change", () => {
      currentSendTokenSymbol = sendTokenSelect.value;
      updateSendAvailableLabel();
    });
  }

  if (btnOpenReceive) {
    btnOpenReceive.addEventListener("click", () => {
      const v = loadVault();
      const acc = getActiveAccount(v);
      if (!acc || !acc.address) {
        showMessage("No wallet address.");
        return;
      }
      receiveAddress.textContent = acc.address;
      showScreen("screen-receive");
    });
  }

  if (btnCopyReceive) {
    btnCopyReceive.addEventListener("click", () => {
      const a = receiveAddress.textContent.trim();
      if (!a) return;
      navigator.clipboard.writeText(a).then(() => showMessage("Address copied."));
    });
  }

  if (btnFaucet) {
    btnFaucet.addEventListener("click", openFaucetForCurrentAddress);
  }

  if (btnImportToken) {
    btnImportToken.addEventListener("click", async () => {
      if (!provider) {
        showMessage("RPC not configured.");
        return;
      }
      const addrRaw = await openInlinePrompt({
        title: "Import token",
        message: "Token contract address (0x...):",
        placeholder: "0x..."
      });
      if (!addrRaw) return;
      let addr = addrRaw.trim();
      if (!addr.startsWith("0x") || addr.length !== 42) {
        showMessage("Enter a valid token address.");
        return;
      }
      const tokens = loadTokensConfig();
      if (tokens.some((t) => t.address && t.address.toLowerCase() === addr.toLowerCase())) {
        showMessage("Token already added.");
        return;
      }
      let symbol = "";
      let decimals = 18;
      try {
        const c = new ethers.Contract(addr, ERC20_ABI, provider);
        symbol = await withRetry(() => c.symbol(), { tries: 2, baseDelay: 200 });
        decimals = await withRetry(() => c.decimals(), { tries: 2, baseDelay: 200 });
      } catch (e) {
        symbol =
          (await openInlinePrompt({
            title: "Token symbol",
            message: "Token symbol (e.g. USDT):"
          })) || "";
        const decStr =
          (await openInlinePrompt({
            title: "Token decimals",
            message: "Token decimals (e.g. 6 or 18):"
          })) || "18";
        const decParsed = parseInt(decStr, 10);
        decimals = isNaN(decParsed) ? 18 : decParsed;
      }
      symbol = (symbol || "").toUpperCase().trim();
      if (!symbol) {
        showMessage("Could not determine token symbol.");
        return;
      }
      const name = symbol;
      const newToken = {
        id: "custom-" + Date.now(),
        symbol,
        name,
        address: addr,
        icon: null,
        decimals
      };
      tokens.push(newToken);
      saveTokensConfig(tokens);
      tokenConfig = tokens;
      tokenContracts[symbol] = new ethers.Contract(addr, ERC20_ABI, provider);
      renderTokenList();
      refreshSendTokenOptions();
      refreshSwapTokenOptions();
      showMessage("Token added.");
      refreshBalances();
    });
  }

  if (btnOpenSwap) {
    btnOpenSwap.addEventListener("click", () => {
      const v = loadVault();
      const acc = getActiveAccount(v);
      if (!v || !acc) {
        showMessage("No wallet.");
        return;
      }
      if (swapAddressDisplay) {
        swapAddressDisplay.textContent = shortAddr(acc.address);
      }
      swapFromSymbol = "USDC";
      swapToSymbol = "EURC";
      refreshSwapTokenOptions();
      updateSwapAvailableLabel();
      showScreen("screen-swap");
    });
  }

  if (swapFromSelect) {
    swapFromSelect.addEventListener("change", () => {
      swapFromSymbol = swapFromSelect.value;
      updateSwapAvailableLabel();
      if (swapToSelect && swapToSelect.value === swapFromSymbol) {
        const tokens = loadTokensConfig().filter(t => t.address);
        const alt = tokens.find(t => t.symbol !== swapFromSymbol);
        if (alt) {
          swapToSelect.value = alt.symbol;
          swapToSymbol = alt.symbol;
        }
      }
    });
  }

  if (swapToSelect) {
    swapToSelect.addEventListener("change", () => {
      swapToSymbol = swapToSelect.value;
    });
  }

  if (btnSwapReview) {
    btnSwapReview.addEventListener("click", async () => {
      if (!swapAmountIn) return;

      const amtStr = (swapAmountIn.value || "").trim();
      const fromSymbol = swapFromSelect ? swapFromSelect.value : (swapFromSymbol || "USDC");
      const toSymbol   = swapToSelect   ? swapToSelect.value   : (swapToSymbol   || "EURC");

      if (!fromSymbol || !toSymbol || fromSymbol === toSymbol) {
        showMessage("Pick two different tokens.");
        return;
      }

      if (!amtStr || isNaN(Number(amtStr)) || Number(amtStr) <= 0) {
        showMessage("Enter a valid amount.");
        return;
      }

      const v   = loadVault();
      const acc = getActiveAccount(v);
      if (!v || !acc) {
        showMessage("No wallet.");
        return;
      }

      const fromMeta = getTokenBySymbol(fromSymbol);
      const toMeta   = getTokenBySymbol(toSymbol);

      if (!fromMeta || !toMeta) {
        showMessage("Invalid token selection.");
        return;
      }

      const avail = typeof tokenBalances[fromSymbol] === "number" ? tokenBalances[fromSymbol] : 0;
      if (Number(amtStr) > avail + 1e-12) {
        showMessage("Insufficient " + fromSymbol + " balance.");
        return;
      }

      const isFromNative = isNativeUsdcToken(fromMeta);
      const isToNative   = isNativeUsdcToken(toMeta);

      let estimatedOutText = toSymbol;
      let feeText          = "";

      try {
        const p = provider || new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);
        if (!provider) provider = p;

        try {
          const gasPrice = await withRetry(
            () => p.getGasPrice(),
            { tries: 3, baseDelay: 200 }
          );

          const approxGasLimit = ethers.BigNumber.from("350000");
          const feeWei = gasPrice.mul(approxGasLimit);

          const feeUsdc = ethers.utils.formatEther(feeWei);
          feeText = feeUsdc + " USDC";
        } catch (e) {
          feeText = "Unknown";
        }

        if ((isFromNative && toMeta.symbol === "WUSDC") ||
            (fromMeta.symbol === "WUSDC" && isToNative)) {

          const n = Number(amtStr);
          if (!isNaN(n)) {
            estimatedOutText = "≈ " + n.toFixed(6) + " " + toSymbol;
          }
        } else if (CONFIG.FACTORY_ADDRESS && CONFIG.ROUTER_ADDRESS) {
          const factory = new ethers.Contract(CONFIG.FACTORY_ADDRESS, FACTORY_ABI, p);

          const poolTokenIn  = isFromNative ? CONFIG.WUSDC_ADDRESS : fromMeta.address;
          const poolTokenOut = isToNative   ? CONFIG.WUSDC_ADDRESS : toMeta.address;

          if (poolTokenIn && poolTokenOut) {
            const route = await buildSwapRoute(factory, poolTokenIn, poolTokenOut, p);
            if (route && route.hops && route.hops.length) {
              const estOut = await estimateOutputForRoute(
                route,
                poolTokenIn,
                poolTokenOut,
                Number(amtStr),
                p
              );
              if (estOut != null && isFinite(estOut)) {
                estimatedOutText = "≈ " + estOut.toFixed(6) + " " + toSymbol;
              }
            }
          }
        }
      } catch (e) {
        if (!feeText) feeText = "Unknown";
      }

      pendingSwapInfo = {
        fromSymbol,
        toSymbol,
        amount: amtStr
      };

      if (swapReviewFrom) {
        swapReviewFrom.textContent = amtStr + " " + fromSymbol;
      }
      if (swapReviewTo) {
        swapReviewTo.textContent = estimatedOutText;
      }
      if (swapReviewNetwork) {
        swapReviewNetwork.textContent = CONFIG.NETWORK_NAME || "ARC Testnet";
      }
      if (swapReviewFee) {
        swapReviewFee.textContent = feeText || "Unknown";
      }

      showScreen("screen-swap-review");
    });
  }

  if (btnSwapReviewBack) {
    btnSwapReviewBack.addEventListener("click", () => {
      showScreen("screen-swap");
    });
  }
  if (btnSwapCancel) {
    btnSwapCancel.addEventListener("click", () => {
      showScreen("screen-swap");
    });
  }

  if (btnSwapConfirm) {
    btnSwapConfirm.addEventListener("click", () => {
      if (!pendingSwapInfo) {
        showMessage("No swap to confirm.");
        return;
      }
      const { fromSymbol, toSymbol, amount } = pendingSwapInfo;
      pendingSwapInfo = null;
      performSwap(fromSymbol, toSymbol, amount);
    });
  }

  async function performSwap(fromSymbol, toSymbol, amtStr) {
    try {
      const v   = loadVault();
      const acc = getActiveAccount(v);
      if (!v || !acc) {
        showMessage("No wallet.");
        return;
      }

      const fromMeta = getTokenBySymbol(fromSymbol);
      const toMeta   = getTokenBySymbol(toSymbol);

      if (!fromMeta) {
        showMessage("Invalid from token.");
        return;
      }
      if (!toMeta) {
        showMessage("Invalid to token.");
        return;
      }

      const isFromNative = isNativeUsdcToken(fromMeta);
      const isToNative   = isNativeUsdcToken(toMeta);

      if (isFromNative && isToNative) {
        showMessage("Nothing to swap.");
        return;
      }

      if (isFromNative && toMeta.symbol === "WUSDC") {
        try {
          showMessage("Wrapping USDC to WUSDC...");
          const p = new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);
          let wallet;
          if (acc.mnemonic) {
            const hd   = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
            const path = acc.path || "m/44'/60'/0'/0/0";
            const child = hd.derivePath(path);
            wallet = new ethers.Wallet(child.privateKey, p);
          } else if (acc.privateKey) {
            wallet = new ethers.Wallet(acc.privateKey, p);
          } else {
            showMessage("No key for this account.");
            return;
          }

          const wusdc = new ethers.Contract(CONFIG.WUSDC_ADDRESS, ["function deposit() payable"], wallet);
          const dec = fromMeta.decimals || 6;
          const amountIn = ethers.utils.parseUnits(amtStr, dec);

          const tx = await withRetry(
            () => wusdc.deposit({ value: amountIn }),
            { tries: 3, baseDelay: 400 }
          );
          pushHistory({
            time: Date.now(),
            type: "wrap",
            token: "USDC→WUSDC",
            amount: Number(amtStr).toFixed(6),
            from: wallet.address,
            to: wallet.address,
            txHash: tx.hash || null
          });
          await withRetry(() => tx.wait(), { tries: 3, baseDelay: 700 });
          showMessage("Wrapped.");
          showAppPage("wallet");
          setTimeout(refreshBalances, 1500);
          return;
        } catch (e) {
          showMessage("Wrap failed.");
          return;
        }
      }

      if (fromMeta.symbol === "WUSDC" && isToNative) {
        try {
          showMessage("Unwrapping WUSDC to USDC...");
          const p = new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);
          let wallet;
          if (acc.mnemonic) {
            const hd   = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
            const path = acc.path || "m/44'/60'/0'/0/0";
            const child = hd.derivePath(path);
            wallet = new ethers.Wallet(child.privateKey, p);
          } else if (acc.privateKey) {
            wallet = new ethers.Wallet(acc.privateKey, p);
          } else {
            showMessage("No key for this account.");
            return;
          }

          const wusdc = new ethers.Contract(
            CONFIG.WUSDC_ADDRESS,
            ["function withdraw(uint256) external"],
            wallet
          );
          const dec = fromMeta.decimals || 6;
          const amountIn = ethers.utils.parseUnits(amtStr, dec);

          const tx = await withRetry(
            () => wusdc.withdraw(amountIn),
            { tries: 3, baseDelay: 400 }
          );
          pushHistory({
            time: Date.now(),
            type: "unwrap",
            token: "WUSDC→USDC",
            amount: Number(amtStr).toFixed(6),
            from: wallet.address,
            to: wallet.address,
            txHash: tx.hash || null
          });
          await withRetry(() => tx.wait(), { tries: 3, baseDelay: 700 });
          showMessage("Unwrapped.");
          showAppPage("wallet");
          setTimeout(refreshBalances, 1500);
          return;
        } catch (e) {
          showMessage("Unwrap failed.");
          return;
        }
      }

      const avail = typeof tokenBalances[fromSymbol] === "number" ? tokenBalances[fromSymbol] : 0;
      if (Number(amtStr) > avail + 1e-12) {
        showMessage("Insufficient " + fromSymbol + " balance.");
        return;
      }

      if (!CONFIG.RPC_URL || !CONFIG.ROUTER_ADDRESS || !CONFIG.FACTORY_ADDRESS || !CONFIG.PERMIT2_ADDRESS) {
        showMessage("Swap not configured.");
        return;
      }

      showMessage("Preparing swap...");

      const p = provider || new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);
      if (!provider) provider = p;

      let wallet;
      if (acc.mnemonic) {
        const hd   = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
        const path = acc.path || "m/44'/60'/0'/0/0";
        const child = hd.derivePath(path);
        wallet = new ethers.Wallet(child.privateKey, p);
      } else if (acc.privateKey) {
        wallet = new ethers.Wallet(acc.privateKey, p);
      } else {
        showMessage("No key for this account.");
        return;
      }

      const net = await withRetry(() => p.getNetwork(), { tries: 3, baseDelay: 300 });
      if (Number(net.chainId) !== Number(CONFIG.CHAIN_ID_DEC)) {
        showMessage("Wrong RPC (chainId mismatch).");
        return;
      }

      const poolTokenIn  = isFromNative ? CONFIG.WUSDC_ADDRESS : fromMeta.address;
      const poolTokenOut = isToNative   ? CONFIG.WUSDC_ADDRESS : toMeta.address;

      if (!poolTokenIn || !poolTokenOut) {
        showMessage("This pair is not supported.");
        return;
      }

      const factory = new ethers.Contract(CONFIG.FACTORY_ADDRESS, FACTORY_ABI, p);
      const route = await buildSwapRoute(factory, poolTokenIn, poolTokenOut, p);

      if (!route || !route.hops || !route.hops.length) {
        showMessage("Pool / route not found for this pair.");
        return;
      }

      let fromDec = typeof fromMeta.decimals === "number" ? fromMeta.decimals : 6;
      let fromContract = null;

      if (!isFromNative) {
        fromContract = new ethers.Contract(fromMeta.address, ERC20_ABI, p);
        try {
          const d = await withRetry(() => fromContract.decimals(), { tries: 2, baseDelay: 200 });
          if (typeof d === "number" && !isNaN(d)) fromDec = d;
        } catch (e) {}
      }

      const amountIn = ethers.utils.parseUnits(amtStr, fromDec);

if (!isFromNative) {
  const PERMIT2_ABI = [
    "function allowance(address owner,address token,address spender) view returns (uint160 amount,uint48 expiration,uint48 nonce)",
    "function approve(address token,address spender,uint160 amount,uint48 expiration)",
    "function approve(address token,address spender,uint160 amount,uint48 expiration,uint48 nonce)"
  ];

  const permit2 = new ethers.Contract(CONFIG.PERMIT2_ADDRESS, PERMIT2_ABI, p);

  const erc20AllowanceToPermit2 = await withRetry(
    () => fromContract.allowance(wallet.address, CONFIG.PERMIT2_ADDRESS),
    { tries: 3, baseDelay: 300 }
  );

  if (erc20AllowanceToPermit2.lt(amountIn)) {
    const approvePermit2Tx = await withRetry(
      () => fromContract.connect(wallet).approve(CONFIG.PERMIT2_ADDRESS, ethers.constants.MaxUint256),
      { tries: 3, baseDelay: 400 }
    );
    await withRetry(() => approvePermit2Tx.wait(), { tries: 3, baseDelay: 700 });
  }

  const allowanceData = await withRetry(
    () => permit2.allowance(wallet.address, fromMeta.address, CONFIG.ROUTER_ADDRESS),
    { tries: 3, baseDelay: 300 }
  );

  const permit2Amt = ethers.BigNumber.from(allowanceData[0].toString());
  const permit2Exp = Number(allowanceData[1].toString());
  const permit2Nonce = Number(allowanceData[2].toString());

  const nowSec = Math.floor(Date.now() / 1000);
  const EXP_MAX = 281474976710655;
  const desiredExp = Math.min(nowSec + 60 * 60 * 24 * 365, EXP_MAX);

  const expTooSoon = !permit2Exp || permit2Exp < (nowSec + 60 * 10);

  if (permit2Amt.lt(amountIn) || expTooSoon) {
    const maxUint160 = ethers.BigNumber.from("0xffffffffffffffffffffffffffffffffffffffff");

    let approveTx;

    try {
      approveTx = await withRetry(
        () => permit2.connect(wallet)["approve(address,address,uint160,uint48)"](
          fromMeta.address,
          CONFIG.ROUTER_ADDRESS,
          maxUint160,
          desiredExp
        ),
        { tries: 3, baseDelay: 400 }
      );
    } catch (e) {
      approveTx = await withRetry(
        () => permit2.connect(wallet)["approve(address,address,uint160,uint48,uint48)"](
          fromMeta.address,
          CONFIG.ROUTER_ADDRESS,
          maxUint160,
          desiredExp,
          permit2Nonce
        ),
        { tries: 3, baseDelay: 400 }
      );
    }

    await withRetry(() => approveTx.wait(), { tries: 3, baseDelay: 700 });
  }
}

      const UR_ABI = [
        "function execute(bytes commands, bytes[] inputs, uint256 deadline) payable"
      ];
      const router = new ethers.Contract(CONFIG.ROUTER_ADDRESS, UR_ABI, wallet);

      const path = encodeV3PathFromHops(route.hops);
      const deadline = Math.floor(Date.now() / 1000) + 60 * 15;

      const V3_SWAP_EXACT_IN = "0x00";
      const WRAP_NATIVE      = "0x0b";
      const UNWRAP_NATIVE    = "0x0c";

      const inputs = [];
      let commands = "0x";
      let txValue = ethers.BigNumber.from(0);

      if (isFromNative && !isToNative) {
        commands += WRAP_NATIVE.slice(2) + V3_SWAP_EXACT_IN.slice(2);
        txValue = amountIn;

        const wrapInput = ethers.utils.defaultAbiCoder.encode(
          ["address", "uint256"],
          [CONFIG.ROUTER_ADDRESS, amountIn]
        );
        inputs.push(wrapInput);

        const swapInput = ethers.utils.defaultAbiCoder.encode(
          ["address", "uint256", "uint256", "bytes", "bool"],
          [wallet.address, amountIn, ethers.BigNumber.from(0), path, false]
        );
        inputs.push(swapInput);
      } else if (!isFromNative && isToNative) {
        commands += V3_SWAP_EXACT_IN.slice(2) + UNWRAP_NATIVE.slice(2);

        const swapInput = ethers.utils.defaultAbiCoder.encode(
          ["address", "uint256", "uint256", "bytes", "bool"],
          [CONFIG.ROUTER_ADDRESS, amountIn, ethers.BigNumber.from(0), path, true]
        );
        inputs.push(swapInput);

        const unwrapInput = ethers.utils.defaultAbiCoder.encode(
          ["address", "uint256"],
          [wallet.address, ethers.BigNumber.from(0)]
        );
        inputs.push(unwrapInput);
      } else {
        commands += V3_SWAP_EXACT_IN.slice(2);

        const swapInput = ethers.utils.defaultAbiCoder.encode(
          ["address", "uint256", "uint256", "bytes", "bool"],
          [wallet.address, amountIn, ethers.BigNumber.from(0), path, true]
        );
        inputs.push(swapInput);
      }

      let gasOpts = {};
      try {
        const gasLimit = await withRetry(
          () => router.estimateGas.execute(commands, inputs, deadline, { value: txValue }),
          { tries: 3, baseDelay: 400 }
        );
        gasOpts = { gasLimit, value: txValue };
      } catch (e) {
        gasOpts = {
          gasLimit: ethers.BigNumber.from("350000"),
          value: txValue
        };
      }

      const tx = await withRetry(
        () => router.execute(commands, inputs, deadline, gasOpts),
        { tries: 3, baseDelay: 500 }
      );

      pushHistory({
        time: Date.now(),
        type: "swap",
        token: fromSymbol + "→" + toSymbol,
        amount: Number(amtStr).toFixed(6),
        from: wallet.address,
        to: wallet.address,
        txHash: tx.hash || null
      });

      await withRetry(() => tx.wait(), { tries: 3, baseDelay: 700 });

      showMessage("Swap completed.");
      showAppPage("wallet");
      setTimeout(() => refreshBalances(), 1500);
    } catch (e) {
      const msg = String(e && e.message ? e.message : e);

      if (/INSUFFICIENT_OUTPUT_AMOUNT|INSUFFICIENT_LIQUIDITY/i.test(msg)) {
        showMessage("Swap failed: pool/liquidity issue or slippage.");
      } else if (/Pool does not exist|invalid pool/i.test(msg)) {
        showMessage("Swap failed: pool not found for this pair/fee.");
      } else if (/insufficient funds(?: for gas)?/i.test(msg)) {
        showMessage("Not enough native gas balance. Keep a small USDC for fees.");
      } else if (/SliceOutOfBounds/i.test(msg)) {
        showMessage("Swap failed: router params mismatch (commands/inputs).");
      } else {
        showMessage("Swap failed.");
      }
    }
  }

  if (btnSendNow) {
    btnSendNow.addEventListener("click", async () => {
      const to = (sendTo.value || "").trim();
      const amtStr = (sendAmount.value || "").trim();
      const sel = document.getElementById("sendTokenSelect");
      const symbol = sel ? sel.value || currentSendTokenSymbol || "USDC" : currentSendTokenSymbol || "USDC";
      const tokenMeta = getTokenBySymbol(symbol);

      if (!to || !to.startsWith("0x")) {
        showMessage("Enter a valid recipient.");
        return;
      }
      if (!amtStr || isNaN(Number(amtStr)) || Number(amtStr) <= 0) {
        showMessage("Enter a valid amount.");
        return;
      }

      const v = loadVault();
      const acc = getActiveAccount(v);
      if (!v || !acc) {
        showMessage("No wallet.");
        return;
      }
      if (!tokenMeta) {
        showMessage("Unknown token.");
        return;
      }

      const isNative = isNativeUsdcToken(tokenMeta);

      const avail = typeof tokenBalances[symbol] === "number" ? tokenBalances[symbol] : 0;
      if (Number(amtStr) > avail + 1e-12) {
        showMessage("Insufficient " + symbol + " balance.");
        return;
      }

      if (!CONFIG.RPC_URL) {
        showMessage("RPC not configured.");
        return;
      }

      try {
        showMessage("Preparing transaction...");

        const p = new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);

        let wallet;
        if (acc.mnemonic) {
          const hd = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
          const path = acc.path || "m/44'/60'/0'/0/0";
          const child = hd.derivePath(path);
          wallet = new ethers.Wallet(child.privateKey, p);
        } else if (acc.privateKey) {
          wallet = new ethers.Wallet(acc.privateKey, p);
        } else {
          showMessage("No key for this account.");
          return;
        }

        const net = await withRetry(() => p.getNetwork(), { tries: 3, baseDelay: 300 });
        if (Number(net.chainId) !== Number(CONFIG.CHAIN_ID_DEC)) {
          showMessage("Wrong RPC (chainId mismatch).");
          return;
        }

        const gasPrice = await withRetry(() => p.getGasPrice(), { tries: 3, baseDelay: 200 });

        let gasLimit;
        let amountBN;
        if (isNative) {
          const dec = typeof tokenMeta.decimals === "number" ? tokenMeta.decimals : 18;
          amountBN = ethers.utils.parseUnits(amtStr, dec);

          gasLimit = await withRetry(() => p.estimateGas({ to, from: wallet.address, value: amountBN }), {
            tries: 3,
            baseDelay: 300
          });
        } else if (tokenMeta.address) {
          const contract = new ethers.Contract(tokenMeta.address, ERC20_ABI, p);

          let dec = typeof tokenMeta.decimals === "number" ? tokenMeta.decimals : 18;
          try {
            const fetchedDec = await withRetry(() => contract.decimals(), { tries: 2, baseDelay: 200 });
            if (typeof fetchedDec === "number" && !isNaN(fetchedDec)) {
              dec = fetchedDec;
            }
          } catch (e) {}

          amountBN = ethers.utils.parseUnits(amtStr, dec);

          gasLimit = await withRetry(() => contract.estimateGas.transfer(to, amountBN, { from: wallet.address }), {
            tries: 3,
            baseDelay: 300
          });
        } else {
          showMessage("Unsupported token type for send.");
          return;
        }

        const feeWei = gasPrice.mul(gasLimit);
        const feeUsdc = ethers.utils.formatEther(feeWei);

        document.getElementById("sendConfirmFrom").textContent = shortAddr(wallet.address);
        document.getElementById("sendConfirmTo").textContent = shortAddr(to);
        document.getElementById("sendConfirmToken").textContent = symbol;
        document.getElementById("sendConfirmAmount").textContent = amtStr + " " + symbol;
        document.getElementById("sendConfirmFee").textContent = feeUsdc + " USDC";

        pendingUiSend = { to, symbol, amountStr: amtStr, isNative };

        showScreen("screen-send-confirm");
      } catch (e) {
        showMessage("Failed to prepare transaction.");
      }
    });
  }

  if (btnSendConfirm) {
    btnSendConfirm.addEventListener("click", async () => {
      if (!pendingUiSend) {
        showMessage("No transaction to send.");
        showScreen("screen-send");
        return;
      }

      const { to, symbol, amountStr, isNative } = pendingUiSend;

      try {
        showMessage("Sending...");

        const v = loadVault();
        const acc = getActiveAccount(v);
        if (!v || !acc) {
          showMessage("No wallet.");
          return;
        }

        if (!CONFIG.RPC_URL) {
          showMessage("RPC not configured.");
          return;
        }

        const tokenMeta = getTokenBySymbol(symbol);
        if (!tokenMeta) {
          showMessage("Unknown token.");
          return;
        }

        const p = new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);

        let wallet;
        if (acc.mnemonic) {
          const hd = ethers.utils.HDNode.fromMnemonic(acc.mnemonic);
          const path = acc.path || "m/44'/60'/0'/0/0";
          const child = hd.derivePath(path);
          wallet = new ethers.Wallet(child.privateKey, p);
        } else if (acc.privateKey) {
          wallet = new ethers.Wallet(acc.privateKey, p);
        } else {
          showMessage("No key for this account.");
          return;
        }

        const net = await withRetry(() => p.getNetwork(), { tries: 3, baseDelay: 300 });
        if (Number(net.chainId) !== Number(CONFIG.CHAIN_ID_DEC)) {
          showMessage("Wrong RPC (chainId mismatch).");
          return;
        }

        if (isNative) {
          const dec = typeof tokenMeta.decimals === "number" ? tokenMeta.decimals : 18;
          const amount = ethers.utils.parseUnits(amountStr, dec);

          let txOpts = { to, value: amount };

          try {
            const gasLimit = await withRetry(() => p.estimateGas({ to, from: wallet.address, value: amount }), {
              tries: 3,
              baseDelay: 300
            });
            txOpts.gasLimit = gasLimit;
          } catch (e) {}

          const tx = await withRetry(() => wallet.sendTransaction(txOpts), { tries: 3, baseDelay: 400 });

          pushHistory({
            time: Date.now(),
            type: "send",
            token: symbol,
            amount: Number(amountStr).toFixed(6),
            from: wallet.address,
            to: to,
            txHash: tx.hash || null
          });

          await withRetry(() => tx.wait(), { tries: 3, baseDelay: 700 });
        } else {
          const contract = new ethers.Contract(tokenMeta.address, ERC20_ABI, p);

          let dec = typeof tokenMeta.decimals === "number" ? tokenMeta.decimals : 18;
          try {
            const fetchedDec = await withRetry(() => contract.decimals(), { tries: 2, baseDelay: 200 });
            if (typeof fetchedDec === "number" && !isNaN(fetchedDec)) {
              dec = fetchedDec;
            }
          } catch (e) {}

          const amount = ethers.utils.parseUnits(amountStr, dec);

          let gasOpts = {};
          try {
            const gasLimit = await withRetry(() => contract.estimateGas.transfer(to, amount, { from: wallet.address }), {
              tries: 3,
              baseDelay: 300
            });
            gasOpts = { gasLimit };
          } catch (e) {}

          const tx = await withRetry(() => contract.connect(wallet).transfer(to, amount, gasOpts), {
            tries: 3,
            baseDelay: 400
          });

          pushHistory({
            time: Date.now(),
            type: "send",
            token: symbol,
            amount: Number(amountStr).toFixed(6),
            from: wallet.address,
            to: to,
            txHash: tx.hash || null
          });

          await withRetry(() => tx.wait(), { tries: 3, baseDelay: 700 });
        }

        pendingUiSend = null;
        showMessage("Sent.");
        await refreshBalances();
        showAppPage("wallet");
      } catch (e) {
        const msg = String(e && e.message ? e.message : e);
        if (/insufficient funds(?: for gas)?/i.test(msg)) {
          showMessage("Not enough native gas balance. Keep a small USDC for fees.");
        } else {
          showMessage("Send failed.");
        }
      }
    });
  }

  if (btnSendReject) {
    btnSendReject.addEventListener("click", () => {
      pendingUiSend = null;
      showScreen("screen-send");
    });
  }

  const btnConnectedDapps = document.getElementById("btnConnectedDapps");
  if (btnConnectedDapps)
    btnConnectedDapps.onclick = async () => {
      const container = document.getElementById("connectedDappsList");
      if (!container) return;

      container.innerHTML = "";
      container.classList.toggle("hidden");

      if (container.classList.contains("hidden")) {
        return;
      }

      const map = await loadPermittedOrigins();
      const keys = Object.keys(map);

      if (keys.length === 0) {
        container.innerHTML = "<div class='sub-note'>No connected sites</div>";
        return;
      }

      keys.forEach((origin) => {
        const row = document.createElement("div");
        row.className = "connected-row";
        row.innerHTML = `
      <span>${origin}</span>
      <button class="btn tiny danger" data-origin="${origin}">Remove</button>
    `;
        container.appendChild(row);
      });

      container.querySelectorAll("button[data-origin]").forEach((btn) => {
        btn.onclick = async () => {
          const origin = btn.getAttribute("data-origin");
          const map = await loadPermittedOrigins();
          if (origin && map[origin]) {
            delete map[origin];
            await savePermittedOrigins(map);
          }
          const row = btn.closest(".connected-row");
          if (row) row.remove();
          if (!container.querySelector(".connected-row")) {
            container.innerHTML = "<div class='sub-note'>No connected sites</div>";
          }
        };
      });
    };

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      startBalancePolling();
    } else {
      hideSensitiveKeys();
      stopBalancePolling();
    }
  });
});

const PERMITTED_ORIGINS_KEY = "casarc_dapp_permissions";

function loadPermittedOrigins() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get([PERMITTED_ORIGINS_KEY], (res) => {
        const map = res && res[PERMITTED_ORIGINS_KEY];
        if (map && typeof map === "object") resolve(map);
        else resolve({});
      });
    } catch (e) {
      resolve({});
    }
  });
}

function savePermittedOrigins(map) {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.set({ [PERMITTED_ORIGINS_KEY]: map || {} }, () => resolve());
    } catch (e) {
      resolve();
    }
  });
}
