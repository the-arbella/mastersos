// The platform extension's start page (design docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.3). A kiosk app
// with any of platform, inject, device_attributes or managed_config starts here instead of at its url:
// chrome-extension://<platform extension id>/start.html (the agent writes it into launch.json). This page asks the background ({cmd:"launch"}); the background puts the request
// header rule in place and only then sends this tab to the app's url (the content scripts are static, so they are
// there already). If that fails, or nothing answers within LAUNCH_TIMEOUT_MS, the page says so and offers Try again and
// Exit (the exam extension's Options menu does not run on extension pages). The page never opens the app's url itself.
(() => {
  "use strict";
  const LAUNCH_TIMEOUT_MS = 20000;
  const EXIT_TIMEOUT_MS = 20000;
  const TEXT = {
    starting: "Starting…",
    failedTitle: "This app could not start.",
    failedBody: "Please ask a teacher.",
    exiting: "Exiting…",
    exitFailed: "Could not leave. Please ask a teacher.",
  };
  const $ = (id) => document.getElementById(id);
  let attempt = 0;

  function show(title, body, actions) {
    $("title").textContent = title;
    document.title = title;
    $("body").textContent = body || "";
    $("body").hidden = !body;
    $("actions").hidden = !actions;
  }

  function failed(body) {
    show(TEXT.failedTitle, body || TEXT.failedBody, true);
    $("retry").focus();
  }

  function start() {
    const mine = ++attempt;
    show(TEXT.starting, "", false);
    const timer = setTimeout(() => {
      if (mine === attempt) failed();
    }, LAUNCH_TIMEOUT_MS);
    try {
      chrome.runtime.sendMessage({ cmd: "launch" }, (r) => {
        void chrome.runtime.lastError;
        if (mine !== attempt) return;
        // ok: the background is sending this tab to the app; nothing else to do here
        if (r && r.ok === true) return;
        clearTimeout(timer);
        failed();
      });
    } catch {
      clearTimeout(timer);
      failed();
    }
  }

  function exit() {
    attempt++;
    show(TEXT.exiting, "", false);
    const timer = setTimeout(() => failed(TEXT.exitFailed), EXIT_TIMEOUT_MS);
    try {
      chrome.runtime.sendMessage({ cmd: "exit" }, (r) => {
        void chrome.runtime.lastError;
        if (r && r.ok === true) return; // requested: the session is ending
        clearTimeout(timer);
        failed(TEXT.exitFailed);
      });
    } catch {
      clearTimeout(timer);
      failed(TEXT.exitFailed);
    }
  }

  $("retry").addEventListener("click", start);
  $("exit").addEventListener("click", exit);
  start();
})();
