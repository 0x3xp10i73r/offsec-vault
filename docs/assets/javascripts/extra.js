/*
  Page conveniences for the notes sections.

  1. Persistent checklists - checkbox state stored per page.
  2. CORS lab image lightbox - click-to-zoom for lab screenshots.
*/


(function () {
  const CHECKS_KEY = "notes.checklist_state.v1";

  /* ------------------------------------------------------- checklists */

  function initChecklists() {
    const boxes = document.querySelectorAll(".task-list-item input[type='checkbox']");
    if (!boxes.length) return;

    const page = window.location.pathname;
    let store = {};
    try {
      store = JSON.parse(localStorage.getItem(CHECKS_KEY) || "{}");
    } catch (e) {}
    const state = store[page] || {};

    boxes.forEach(function (cb, i) {
      cb.removeAttribute("disabled");
      cb.style.cursor = "pointer";
      cb.checked = !!state[i];
      cb.addEventListener("change", function () {
        state[i] = cb.checked;
        store[page] = state;
        try {
          localStorage.setItem(CHECKS_KEY, JSON.stringify(store));
        } catch (e) {}
        update();
      });
    });

    if (boxes.length >= 5 && !document.querySelector(".checklist-progress")) {
      const bar = document.createElement("div");
      bar.className = "checklist-progress";
      bar.innerHTML =
        '<span id="checklist-count"></span>' +
        '<div class="checklist-progress__bar"><div class="checklist-progress__fill" id="checklist-fill"></div></div>' +
        '<button type="button" id="checklist-reset">Reset</button>';

      const article = document.querySelector(".md-content__inner");
      article.prepend(bar);

      bar.querySelector("#checklist-reset").addEventListener("click", function () {
        boxes.forEach(function (cb) { cb.checked = false; });
        delete store[page];
        try {
          localStorage.setItem(CHECKS_KEY, JSON.stringify(store));
        } catch (e) {}
        update();
      });
    }

    function update() {
      const total = boxes.length;
      const done = Array.prototype.filter.call(boxes, function (c) { return c.checked; }).length;
      const pct = total ? Math.round((done / total) * 100) : 0;
      const count = document.getElementById("checklist-count");
      const fill = document.getElementById("checklist-fill");
      if (count) count.textContent = done + " of " + total + " done · " + pct + "%";
      if (fill) fill.style.width = pct + "%";
    }

    update();
  }

  /* --------------------------------------------------------- image lightbox */

  function initCorsImageLightbox() {
    const links = document.querySelectorAll(".cors-lab-image-link");
    if (!links.length) return;

    let overlay = document.querySelector(".cors-image-lightbox");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.className = "cors-image-lightbox";
      overlay.hidden = true;
      overlay.setAttribute("aria-hidden", "true");
      overlay.innerHTML =
        '<div class="cors-image-lightbox__backdrop" data-lightbox-close></div>' +
        '<div class="cors-image-lightbox__dialog" role="dialog" aria-modal="true" aria-label="Expanded CORS lab image">' +
          '<div class="cors-image-lightbox__toolbar">' +
            '<button type="button" data-lightbox-zoom-out aria-label="Zoom out" title="Zoom out">−</button>' +
            '<span class="cors-image-lightbox__zoom-level" data-lightbox-zoom-level>100%</span>' +
            '<button type="button" data-lightbox-zoom-in aria-label="Zoom in" title="Zoom in">+</button>' +
            '<button type="button" data-lightbox-reset aria-label="Reset zoom" title="Reset zoom">Reset</button>' +
            '<button type="button" data-lightbox-close aria-label="Close image" title="Close image">×</button>' +
          '</div>' +
          '<div class="cors-image-lightbox__stage" data-lightbox-stage tabindex="0">' +
            '<img class="cors-image-lightbox__image" data-lightbox-image alt="">' +
          '</div>' +
        '</div>';
      document.body.appendChild(overlay);
    }

    const image = overlay.querySelector("[data-lightbox-image]");
    const level = overlay.querySelector("[data-lightbox-zoom-level]");
    const stage = overlay.querySelector("[data-lightbox-stage]");
    let zoom = 1;

    function updateZoom(nextZoom) {
      zoom = Math.max(0.5, Math.min(3, nextZoom));
      level.textContent = Math.round(zoom * 100) + "%";

      if (zoom === 1 || !image.naturalWidth) {
        image.style.width = "";
        image.classList.remove("is-zoomed");
      } else {
        image.style.width = Math.round(image.naturalWidth * zoom) + "px";
        image.classList.add("is-zoomed");
      }
    }

    function closeLightbox() {
      overlay.hidden = true;
      overlay.setAttribute("aria-hidden", "true");
      document.body.classList.remove("cors-lightbox-open");
    }

    function openLightbox(link) {
      const source = link.querySelector("img");
      image.onload = function () { updateZoom(1); };
      image.src = link.href;
      image.alt = source ? source.alt : "Expanded CORS lab image";
      zoom = 1;
      image.style.width = "";
      image.classList.remove("is-zoomed");
      level.textContent = "100%";
      overlay.hidden = false;
      overlay.setAttribute("aria-hidden", "false");
      document.body.classList.add("cors-lightbox-open");
      if (image.complete) updateZoom(1);
      overlay.querySelector(".cors-image-lightbox__toolbar [data-lightbox-close]").focus();
    }

    if (!overlay.dataset.lightboxBound) {
      overlay.dataset.lightboxBound = "true";
      overlay.querySelectorAll("[data-lightbox-close]").forEach(function (closeTarget) {
        closeTarget.addEventListener("click", closeLightbox);
      });
      overlay.querySelector("[data-lightbox-zoom-in]").addEventListener("click", function () {
        updateZoom(zoom + 0.25);
      });
      overlay.querySelector("[data-lightbox-zoom-out]").addEventListener("click", function () {
        updateZoom(zoom - 0.25);
      });
      overlay.querySelector("[data-lightbox-reset]").addEventListener("click", function () {
        updateZoom(1);
        stage.scrollTo({ top: 0, left: 0, behavior: "smooth" });
      });
      stage.addEventListener("wheel", function (event) {
        if (!event.ctrlKey) return;
        event.preventDefault();
        updateZoom(zoom + (event.deltaY < 0 ? 0.1 : -0.1));
      }, { passive: false });
      window.addEventListener("keydown", function (event) {
        if (overlay.hidden) return;
        if (event.key === "Escape") closeLightbox();
        if (event.key === "+" || event.key === "=") updateZoom(zoom + 0.25);
        if (event.key === "-") updateZoom(zoom - 0.25);
        if (event.key === "0") updateZoom(1);
      });
    }

    links.forEach(function (link) {
      if (link.dataset.lightboxBound) return;
      link.dataset.lightboxBound = "true";
      link.addEventListener("click", function (event) {
        event.preventDefault();
        openLightbox(link);
      });
    });
  }

  /* ------------------------------------------------------------- boot */

  function init() {
    initChecklists();
    initCorsImageLightbox();
  }

  if (typeof document$ !== "undefined") {
    document$.subscribe(init);
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
