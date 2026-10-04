// Click ripple for every button; uses delegation so React-rendered buttons are covered too.
(function () {
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  document.addEventListener("pointerdown", function (e) {
    var btn = e.target.closest(".btn, .theme-toggle, .lp-copy");
    if (!btn || btn.disabled) return;

    var rect = btn.getBoundingClientRect();
    var size = Math.max(rect.width, rect.height) * 2;
    var ripple = document.createElement("span");
    ripple.className = "btn-ripple";
    ripple.style.width = ripple.style.height = size + "px";
    ripple.style.left = e.clientX - rect.left - size / 2 + "px";
    ripple.style.top = e.clientY - rect.top - size / 2 + "px";
    btn.appendChild(ripple);
    ripple.addEventListener("animationend", function () { ripple.remove(); });
  });
})();
