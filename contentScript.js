const s = document.createElement("script");
s.src = chrome.runtime.getURL("inpage.js");
s.async = false;
(document.documentElement || document.head || document.body).appendChild(s);
s.remove();

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const msg = event.data;
  if (!msg || msg.source !== "casarc-inpage") return;

  const { id, method, params } = msg;

  if (method === "arc_universalRouter") {
    chrome.runtime.sendMessage(
      {
        type: "UNIVERSAL_ROUTER_SWAP",
        payload: Array.isArray(params) ? params[0] : params,
        fromPage: true
      },
      (response) => {
        window.postMessage(
          {
            source: "casarc-extension",
            id,
            response
          },
          "*"
        );
      }
    );
    return;
  }

  chrome.runtime.sendMessage(
    {
      type: "RPC_REQUEST",
      method,
      params,
      fromPage: true
    },
    (response) => {
      window.postMessage(
        {
          source: "casarc-extension",
          id,
          response
        },
        "*"
      );
    }
  );
});
