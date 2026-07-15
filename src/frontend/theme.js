(function () {
  "use strict";
  try {
    var saved = localStorage.getItem("fs:theme");
    var theme = saved ? JSON.parse(saved) : null;
    if (theme !== "dark" && theme !== "light") {
      theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    }
    document.documentElement.dataset.theme = theme;
  } catch (_) {
    document.documentElement.dataset.theme = "dark";
  }
})();
