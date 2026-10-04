// Loaded in <head> so the saved theme applies before first paint (no flash).
(function () {
  var KEY = "ssh_monitor_theme";
  var root = document.documentElement;

  function read() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function apply(t) {
    if (t === "light" || t === "dark") root.setAttribute("data-theme", t);
    else root.removeAttribute("data-theme");
  }

  apply(read());

  window.currentTheme = function () {
    var t = root.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  };

  window.toggleTheme = function () {
    var next = window.currentTheme() === "dark" ? "light" : "dark";
    apply(next);
    try { localStorage.setItem(KEY, next); } catch (e) {}
    return next;
  };
})();
