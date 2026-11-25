// Applies the saved color theme before the first paint so the page does not
// flash the wrong palette. Loaded synchronously from <head>; the CSP forbids
// inline scripts, so this lives in its own file.
(function () {
  try {
    var saved = window.localStorage.getItem("pgw-theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  } catch (e) {
    // Storage can be blocked; the system preference still applies.
  }
})();
