(async () => {
  const params = new URLSearchParams(location.search);
  const debug = params.get("debug") === "1";

  const pre = document.createElement("pre");
  pre.style.whiteSpace = "pre-wrap";
  pre.style.fontFamily =
    "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace";
  document.body.appendChild(pre);

  const log = (s) => {
    pre.textContent += s + "\n";
  };

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

  function resolveCreateClient() {
    const candidates = [
      window.supabase,
      window.Supabase,
      window.supabaseJs,
      window.supabasejs,
      window.supabase_lib,
      window.supabaseLib
    ].filter(Boolean);

    for (const c of candidates) {
      if (c && typeof c.createClient === "function") return c.createClient.bind(c);
    }

    for (const k of Object.keys(window)) {
      try {
        const v = window[k];
        if (v && typeof v.createClient === "function") return v.createClient.bind(v);
      } catch (e) {}
    }
    return null;
  }

  function getSupabaseClient() {
    if (window.supabase && window.supabase.auth && typeof window.supabase.auth.getSession === "function") {
      return window.supabase;
    }

    const createClient = resolveCreateClient();
    if (!createClient) return null;

    const c = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: false,
        storage: chromeStorage
      }
    });

    window.supabase = c;
    return c;
  }

  function extractHashTokens() {
    const hash = location.hash && location.hash.startsWith("#") ? location.hash.slice(1) : "";
    const p = new URLSearchParams(hash);
    return {
      access_token: p.get("access_token"),
      refresh_token: p.get("refresh_token")
    };
  }

  async function ensureSessionFromCallback(sb) {
    const u = new URL(location.href);

    const errParam =
      u.searchParams.get("error") ||
      u.searchParams.get("error_code") ||
      u.searchParams.get("error_description");

    if (errParam) {
      throw new Error(String(errParam));
    }

    const code = u.searchParams.get("code");

    if (code && typeof sb.auth.exchangeCodeForSession === "function") {
      const { error } = await sb.auth.exchangeCodeForSession(code);
      if (error) throw error;
      return;
    }

    if (typeof sb.auth.getSessionFromUrl === "function") {
      const { error } = await sb.auth.getSessionFromUrl({ storeSession: true });
      if (!error) return;
    }

    if (typeof sb.auth.setSession === "function") {
      const t = extractHashTokens();
      if (!t.access_token || !t.refresh_token) {
        throw new Error("Token bulunamadı (hash boş).");
      }
      const { error } = await sb.auth.setSession({
        access_token: t.access_token,
        refresh_token: t.refresh_token
      });
      if (error) throw error;
      return;
    }

    throw new Error("No supported callback handler found.");
  }

  try {
    log("Auth Callback (Debug)");
    log("URL: " + location.href);

    const fullUrl = location.href;

    const sb = getSupabaseClient();
    if (!sb || !sb.auth) {
      log("Supabase client not found.");
    } else {
      try {
        await ensureSessionFromCallback(sb);
        const { data, error } = await sb.auth.getSession();
        if (error) throw error;

        const session = data && data.session ? data.session : null;
        if (session && session.user) {
          chrome.runtime.sendMessage(
            { type: "SUPABASE_AUTH_DONE", userId: session.user.id },
            () => {}
          );
          chrome.runtime.sendMessage(
            { type: "SUPABASE_OAUTH_SUCCESS", userId: session.user.id },
            () => {}
          );
          log("Sent SUPABASE_AUTH_DONE / SUPABASE_OAUTH_SUCCESS to extension.");
        } else {
          log("No session after exchange.");
        }
      } catch (e) {
        log("Session error: " + (e && e.message ? e.message : String(e)));
      }
    }

    chrome.runtime.sendMessage({ type: "OAUTH_CALLBACK", url: fullUrl }, (resp) => {
      const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : null;

      if (err) {
        log("sendMessage error: " + err);
      } else {
        log("sendMessage response: " + JSON.stringify(resp));
      }

      if (!debug) {
        setTimeout(() => window.close(), 1200);
      }
    });
  } catch (e) {
    log("Auth callback error: " + (e && e.message ? e.message : String(e)));
  }
})();
