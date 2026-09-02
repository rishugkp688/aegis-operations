(() => {
  let theme;
  try {
    const saved = localStorage.getItem("aegis-operations-theme");
    if (saved === "light" || saved === "dark") theme = saved;
  } catch {
    // Storage may be unavailable in hardened or ephemeral browser contexts.
  }

  if (!theme) {
    theme = window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  window.__aegisOperationsInitialTheme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute(
    "content",
    theme === "light" ? "#f3f5f8" : "#080b11",
  );
})();
