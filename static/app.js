(() => {
  const toggle = document.querySelector(".menu-toggle");
  const nav = document.getElementById("primary-navigation");
  if (!toggle || !nav) return;
  const closeMenu = () => {
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-label", "Open navigation menu");
    nav.classList.remove("is-open");
  };
  toggle.addEventListener("click", () => {
    const open = toggle.getAttribute("aria-expanded") !== "true";
    toggle.setAttribute("aria-expanded", String(open));
    toggle.setAttribute(
      "aria-label",
      open ? "Close navigation menu" : "Open navigation menu",
    );
    nav.classList.toggle("is-open", open);
  });
  nav
    .querySelectorAll("a")
    .forEach((link) => link.addEventListener("click", closeMenu));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeMenu();
  });
  document.querySelectorAll("form[method=post]").forEach((form) => {
    form.addEventListener("submit", () => {
      if (form.dataset.noLoading === "true" || !form.checkValidity()) return;
      const button = form.querySelector("button[type=submit]");
      if (!button || button.disabled) return;
      button.dataset.originalText = button.textContent;
      button.textContent = "Please wait…";
      button.disabled = true;
      form.setAttribute("aria-busy", "true");
    });
  });
})();
