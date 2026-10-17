/*
  Page conveniences for the notes sections.

  1. Command variables - a small box above the first code block, replacing
     <TARGET_IP>, <DOMAIN>, <DC_IP>, <LHOST>, <LPORT> and <USER> in every
     command (including what the copy button writes), remembered in
     localStorage. Only pages that actually contain one of those placeholders
     in a code block get the box.
  2. Persistent checklists - checkbox state stored per page.

  Both are skipped on the blog index and on post pages, where excerpts contain
  code blocks and list items that would otherwise pick them up.
*/


(function () {
  const VARS_KEY = "notes.command_vars.v1";
  const CHECKS_KEY = "notes.checklist_state.v1";

  const DEFAULT_VARS = {
    TARGET_IP: "10.10.11.42",
    DOMAIN: "corp.local",
    DC_IP: "10.10.11.10",
    LHOST: "10.10.14.8",
    LPORT: "4444",
    USER: "jdoe"
  };

  /* ------------------------------------------------ command variables */

  function loadVars() {
    try {
      return Object.assign({}, DEFAULT_VARS, JSON.parse(localStorage.getItem(VARS_KEY) || "{}"));
    } catch (e) {
      return Object.assign({}, DEFAULT_VARS);
    }
  }

  function saveVars(vars) {
    try {
      localStorage.setItem(VARS_KEY, JSON.stringify(vars));
    } catch (e) {
      /* storage unavailable: values still apply to this view */
    }
  }

  /* The syntax highlighter sometimes splits a placeholder into separate spans,
     for example &lt;</span><span class="n">LHOST</span><span class="p">&gt;.
     This pattern matches the placeholder in either form, so substitution works
     whatever Pygments decided to do with the angle brackets. */
  function placeholderPattern(key) {
    return new RegExp(
      "(?:&lt;|<)(?:</span>)?(?:<span[^>]*>)?[ ]*" + key +
      "[ ]*(?:</span>)?(?:<span[^>]*>)?(?:&gt;|>)",
      "g"
    );
  }

  function applyVars(vars) {
    document.querySelectorAll(".md-typeset pre code").forEach(function (codeEl) {
      if (!codeEl.dataset.originalHtml) {
        codeEl.dataset.originalHtml = codeEl.innerHTML;
      }
      let html = codeEl.dataset.originalHtml;
      Object.keys(vars).forEach(function (key) {
        const value = vars[key] || DEFAULT_VARS[key];
        html = html.replace(placeholderPattern(key), value);
      });
      codeEl.innerHTML = html;
    });
  }

  function buildVarsBox() {
    const vars = loadVars();
    const box = document.createElement("div");
    box.className = "cmd-vars";
    box.innerHTML =
      '<div class="cmd-vars__header">' +
        '<span class="cmd-vars__title">Command variables</span>' +
        '<span class="cmd-vars__hint">Applied to every command on this page, and remembered in this browser.</span>' +
        '<button type="button" class="cmd-vars__reset" id="cmd-vars-reset">Reset</button>' +
      "</div>" +
      '<div class="cmd-vars__fields"></div>';

    const fields = box.querySelector(".cmd-vars__fields");
    Object.keys(DEFAULT_VARS).forEach(function (key) {
      const field = document.createElement("div");
      field.className = "cmd-vars__field";
      field.innerHTML =
        '<label for="cmd-var-' + key + '">&lt;' + key + "&gt;</label>" +
        '<input id="cmd-var-' + key + '" type="text" data-var="' + key + '" ' +
        'value="' + vars[key] + '" spellcheck="false" autocomplete="off">';
      fields.appendChild(field);
    });

    box.querySelectorAll("input[data-var]").forEach(function (input) {
      input.addEventListener("input", function () {
        const current = loadVars();
        current[input.dataset.var] = input.value.trim() || DEFAULT_VARS[input.dataset.var];
        saveVars(current);
        applyVars(current);
      });
    });

    box.querySelector("#cmd-vars-reset").addEventListener("click", function () {
      saveVars(DEFAULT_VARS);
      box.querySelectorAll("input[data-var]").forEach(function (input) {
        input.value = DEFAULT_VARS[input.dataset.var];
      });
      applyVars(DEFAULT_VARS);
    });

    return box;
  }

  /* The box only earns its place on a page that actually has placeholders to
     fill in: at least one code block containing <TARGET_IP>, <DOMAIN>, <DC_IP>,
     <LHOST>, <LPORT> or <USER>. A page with unrelated commands, or one that
     only mentions the placeholders in prose, gets no box. */
  function pageUsesVars(article) {
    const keys = Object.keys(DEFAULT_VARS);
    const blocks = article.querySelectorAll("pre code");
    const probe = document.createElement("div");
    for (let i = 0; i < blocks.length; i++) {
      // Decode the markup back to text first, so a placeholder split across
      // spans still reads as <LHOST>
      probe.innerHTML = blocks[i].dataset.originalHtml || blocks[i].innerHTML;
      const text = probe.textContent || "";
      for (let k = 0; k < keys.length; k++) {
        if (text.indexOf("<" + keys[k] + ">") !== -1) {
          return true;
        }
      }
    }
    return false;
  }

  function insertVarsBox() {
    const article = document.querySelector(".md-content__inner");
    if (!article || article.querySelector(".cmd-vars")) return;
    if (!pageUsesVars(article)) return;

    const firstCode = article.querySelector("pre");
    if (!firstCode || !firstCode.parentNode) return;

    firstCode.parentNode.insertBefore(buildVarsBox(), firstCode);
    applyVars(loadVars());
  }

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
      const anchor = article.querySelector(".cmd-vars");
      if (anchor && anchor.nextSibling) {
        anchor.parentNode.insertBefore(bar, anchor.nextSibling);
      } else {
        article.prepend(bar);
      }

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
    // Blog listings embed post excerpts: no variables box, no checklist counters.
    if (document.querySelector(".md-post--excerpt")) return;
    // Both features belong to the notes sections, not to blog posts.
    if (window.location.pathname.indexOf("/blog/") === 0) return;

    insertVarsBox();
    initChecklists();
    initCorsImageLightbox();
  }

  if (typeof document$ !== "undefined") {
    document$.subscribe(init);
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
