/** Iconos SVG lineales (estilo Lucide) para ARPegio. */
(function (global) {
  const PATHS = {
    settings:
      '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    "alert-triangle":
      '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    layers:
      '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    search:
      '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    radar:
      '<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/><path d="M7.76 16.24a6 6 0 0 1-8.49 0"/><path d="M4.93 19.07a10 10 0 0 1 0-14.14"/>',
    "check-circle":
      '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    "chevron-right": '<polyline points="9 18 15 12 9 6"/>',
    lock:
      '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  };

  function icon(name, opts = {}) {
    const {
      size = 16,
      className = "icon",
      stroke = "currentColor",
      fill = "none",
      title = "",
    } = opts;
    const body = PATHS[name] || "";
    const label = title ? `<title>${title}</title>` : "";
    return `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="${fill}" stroke="${stroke}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="${title ? "false" : "true"}" role="img">${label}${body}</svg>`;
  }

  function iconLabel(name, text, opts = {}) {
    const { labelClass = "icon-label" } = opts;
    return `<span class="${labelClass}">${icon(name, opts)}<span>${text}</span></span>`;
  }

  function terminalPrefix(kind = "info") {
    return icon("chevron-right", {
      size: 10,
      className: `icon icon-chevron icon-chevron--${kind}`,
    });
  }

  function hydrateIcons(root = document) {
    root.querySelectorAll("[data-icon]").forEach((el) => {
      const name = el.dataset.icon;
      const size = Number(el.dataset.iconSize) || 16;
      const only = el.dataset.iconOnly === "true";
      el.insertAdjacentHTML(
        "afterbegin",
        icon(name, {
          size,
          className: el.dataset.iconClass || "icon",
          title: el.getAttribute("aria-label") || "",
        })
      );
      if (only) el.textContent = "";
    });
  }

  global.ArpegioIcons = {
    icon,
    iconLabel,
    terminalPrefix,
    hydrateIcons,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => hydrateIcons());
  } else {
    hydrateIcons();
  }
})(window);
