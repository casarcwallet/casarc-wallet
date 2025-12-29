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

(function initSupabaseClient() {
  try {
    const g = typeof globalThis !== "undefined" ? globalThis : self;

    if (
      g.supabase &&
      g.supabase.auth &&
      typeof g.supabase.auth.getSession === "function"
    ) {
      return;
    }

    let createClient = null;

    const candidates = [
      g.supabase,
      g.Supabase,
      g.supabaseJs,
      g.supabasejs,
      g.supabase_lib,
      g.supabaseLib
    ].filter(Boolean);

    for (const c of candidates) {
      if (c && typeof c.createClient === "function") {
        createClient = c.createClient.bind(c);
        break;
      }
    }

    if (!createClient) {
      for (const k of Object.keys(g)) {
        try {
          const v = g[k];
          if (v && typeof v.createClient === "function") {
            createClient = v.createClient.bind(v);
            break;
          }
        } catch (e) {}
      }
    }

    if (!createClient) {
      return;
    }

    const hasChromeStorage =
      typeof chrome !== "undefined" &&
      chrome.storage &&
      chrome.storage.local &&
      typeof chrome.storage.local.get === "function";

    const storageImpl = hasChromeStorage ? chromeStorage : undefined;

    g.supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        flowType: "pkce",
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: false,
        ...(storageImpl ? { storage: storageImpl } : {})
      }
    });
  } catch (e) {}
})();
