---
date: 2026-01-22
categories:
  - Meta
  - Tooling
tags:
  - MkDocs
  - GitHub Pages
  - Documentation
authors:
  - 0x3xp10i73r
description: "How these notes are built: MkDocs with the Material theme, two small JavaScript conveniences for command-heavy pages, and a GitHub Actions deploy."
---

# How this site is built

![Abstract dark ink texture](../../assets/images/cover-ink.jpg){ .page-cover-img }

Every so often someone asks what the notes are running on, so this is the whole thing written down: the stack, the two custom features that make command-heavy pages less painful, and the mistakes I made along the way.

<!-- more -->

## Why a self-hosted site

I keep notes in Markdown files in a Git repository. That part was never in question — plain text files survive tool changes, and I can search them with `grep`. What I wanted on top of that was navigation, full-text search, and a place to put longer writeups, without turning note-taking into a publishing workflow.

| Requirement | MkDocs Material | Hosted wiki |
| :--- | :--- | :--- |
| Search across every page, offline, no third party | Yes | Usually server-side |
| Full control over layout and CSS | Yes | Limited |
| Markdown in Git as the source of truth | Yes | Sometimes, with quirks |
| Blog with categories and tags | Yes, blog plugin | Not really |
| Free hosting with a custom domain | Yes | Paid tiers |
| Custom JavaScript when I need it | Yes | No |

GitBook is genuinely good software, and if you want a hosted editor it is the right choice. I wanted the site to be reproducible from a repository with a config file, so MkDocs won.

## Structure

```text
notes/
├── mkdocs.yml                   # site configuration: theme, plugins, navigation
├── requirements.txt
├── .gitbook.yaml                # optional GitBook sync
├── .github/workflows/deploy.yml # build and deploy on push
└── docs/
    ├── index.md
    ├── about.md
    ├── SUMMARY.md               # navigation mirror for GitBook
    ├── assets/
    │   ├── images/
    │   ├── stylesheets/extra.css
    │   └── javascripts/extra.js
    ├── recon/
    ├── web-bugbounty/
    ├── active-directory/
    ├── red-team/
    ├── privesc/
    ├── android/
    ├── cloud-mobile/
    ├── checklists-arsenal/
    └── blog/
        ├── .authors.yml
        ├── index.md
        └── posts/*.md
```

Navigation is defined explicitly in `mkdocs.yml`. Auto-discovery is fine at ten pages and actively unhelpful at forty, because ordering the sections is part of the product.

## Theme configuration

The theme is Material with a single dark palette and about 400 lines of CSS on top. Two decisions shape the whole look:

- **Pure black background.** Not "dark grey" — actual `#000`. On an OLED display it means the pixels that are not text are genuinely off, which is easier on the eyes when you are reading at 2am.
- **The Dracula palette on top of it.** The same sixteen colours a lot of people already run in their editor: `#f8f8f2` for text, `#bd93f9` purple for links, `#ff79c6` pink for the active item and for keywords in code, `#50fa7b`, `#f1fa8c`, `#8be9fd` and `#ffb86c` for everything the highlighter needs. Nothing is invented, and nothing is a gradient — flat colour, hairline borders, no blur, no shadows beyond the ones the theme ships with.

The navigation lives entirely in the left sidebar — no top tab bar — because that is the layout that works best when the navigation tree is deep. Section names render as small uppercase group labels and the current page is marked with a pink rail.

```yaml
theme:
  name: material
  font:
    text: Inter
    code: JetBrains Mono
  palette:
    scheme: slate              # one dark palette, no toggle
    primary: custom
    accent: custom
  features:
    - navigation.instant
    - navigation.tracking
    - navigation.indexes       # section landing pages
    - navigation.top
    - toc.follow
    - search.suggest
    - search.highlight
    - content.code.copy
    - content.tabs.link
```

Section names come from the navigation, not from the theme:

```yaml
# mkdocs.yml
nav:
  - Recon:
      - recon/index.md
      - Passive discovery:
          - Subdomains and virtual hosts: recon/subdomain-enumeration.md
          - OSINT and dorking: recon/osint-dorking.md
```

```yaml
# docs/recon/subdomain-enumeration.md
---
title: "Subdomains and virtual hosts"
description: "Finding subdomains and vhosts that do not show up in DNS."
---
```

The Dracula colours are set as CSS variables in `docs/assets/stylesheets/extra.css`, overriding the theme's own palette variables — `--md-default-bg-color` for the black background, `--md-typeset-a-color` for link purple, and the `--md-code-hl-*` group for syntax highlighting, which is what makes code blocks come out in Dracula colours instead of Material's blues:

```css
[data-md-color-scheme="slate"] {
  --md-default-bg-color: #000000;
  --md-typeset-a-color: #bd93f9;
  --md-code-bg-color: #191a21;
  --md-code-hl-keyword-color: #ff79c6;
  --md-code-hl-string-color: #f1fa8c;
  --md-code-hl-function-color: #50fa7b;
  --md-code-hl-comment-color: #6272a4;
}
```

What the rest of the CSS does is small: tightens typography for reference pages, widens the layout to 68rem so the text column is not cramped, gives code blocks, tables and admonitions a consistent flat treatment, recolours the twelve admonition types to the nearest Dracula colour, keeps the heading anchors hidden until you hover a heading, and marks the active item in the sidebar and the table of contents.

There is no light theme. I read these pages in a dark terminal all day, and maintaining a second palette for a site I read at night was work that bought me nothing. If you want a light mode, add a second entry to `theme.palette` in `mkdocs.yml` and a matching `[data-md-color-scheme="default"]` block; the rest of the CSS inherits from the theme's variables.

## Page covers

Every page opens with a cover image, the way a GitBook page does. Rather than repeat a `cover:` line in forty files, the default comes from the page's section, worked out in `overrides/main.html` from the page URL:

```jinja
{% set covers = {
  "recon": "assets/images/cover-network.jpg",
  "active-directory": "assets/images/cover-identity.jpg",
  "cloud-mobile": "assets/images/cover-cloud.jpg"
} %}
{% set section = "" if url in ("", ".", "./") else url.split("/")[0] %}
{% set cover = covers.get(section) %}
```

A page that wants something else overrides it, and a page that wants no cover at all turns it off:

```yaml
---
cover: assets/images/cover-ink.jpg
---
```

```yaml
---
cover: false
---
```

The covers are 1584x396 JPEGs — LinkedIn profile header proportions, which is a 4:1 box — placed with `object-fit: cover` so they line up regardless of the source image. Blog posts carry the same cover inline in the Markdown instead: the blog template replaces the block the override hooks into, and it needs the cover inside the post content anyway so it survives into the excerpt markup.

## Navigation that hides its depth

The nav is three levels deep in places, which is where a sidebar earns its keep. Section names are small uppercase group labels, the middle level holds collapsible sub-groups, and the pages inside a sub-group sit behind a hairline so the nesting is visible without a colour change:

```
RECON
  Passive discovery
    Subdomains and virtual hosts
    OSINT and dorking
  Active enumeration
    Ports and services
    Web recon and fuzzing
```

Every level is collapsible, and the section you are in expands on its own. Groups that hold a single page — Enumeration, in Active Directory — are a deliberate exception: collapsing for one item is noise.

## Command variables

The single most annoying thing about writing these notes was find-and-replacing `<TARGET_IP>` in twenty code blocks every time I moved to a new target. The second most annoying thing was forgetting to.

So a couple of dozen lines of JavaScript insert a small box above the first code block, but only on a page whose commands actually contain one of the placeholders. The check reads the decoded text of every code block first, because the highlighter splits `<LHOST>` into three spans often enough that a plain string match misses it:

```javascript
const DEFAULT_VARS = {
  TARGET_IP: "10.10.11.42",
  DOMAIN: "corp.local",
  DC_IP: "10.10.11.10",
  LHOST: "10.10.14.8",
  LPORT: "4444",
  USER: "jdoe"
};

function applyVars(vars) {
  document.querySelectorAll(".md-typeset pre code").forEach(function (codeEl) {
    // Keep the original markup so repeated edits never compound
    if (!codeEl.dataset.originalHtml) {
      codeEl.dataset.originalHtml = codeEl.innerHTML;
    }
    let html = codeEl.dataset.originalHtml;
    Object.keys(vars).forEach(function (key) {
      const value = vars[key] || DEFAULT_VARS[key];
      html = html
        .replace(new RegExp("&lt;" + key + "&gt;", "g"), value) // escaped in the DOM
        .replace(new RegExp("<" + key + ">", "g"), value);      // raw form
    });
    codeEl.innerHTML = html;
  });
}
```

Values are stored in `localStorage`, so they persist across page navigation, and the box has a **Reset** button for when I move to a different engagement.

Two details that matter more than they should:

1. **The copy button reads the DOM.** Material's copy button copies the current text of the code element, so mutating `innerHTML` (rather than overlaying text with CSS) means what you copy is what you see. If you implement this with a CSS overlay, you will copy the placeholders and not notice until a payload lands somewhere it should not.
2. **Store the original markup.** If you keep re-applying substitutions to the same element, the second pass replaces the values inside already-substituted text. Keeping the pristine HTML in `data-originalHtml` avoids the whole class of bug.

## Checklists that remember where you are

The other annoyance was working through a long checklist over several days. Material renders `- [ ]` task lists as disabled checkboxes, so the state is read from the Markdown and cannot be changed in the browser.

About forty lines of JavaScript fixes that: it enables the checkboxes, stores the state per page path in `localStorage`, and shows a counter with a **Reset** button on pages with enough items to be worth tracking. It is the same idea as the command variables — small, local, no backend.

If you are copying this for your own site, the one thing to watch out for is `navigation.instant`, Material's client-side navigation. Your script only runs once on the first page load, so anything you do on page render has to be registered on the `document$` observable rather than `DOMContentLoaded`:

```javascript
if (typeof document$ !== "undefined") {
  document$.subscribe(init);   // runs on every page, including instant navigation
} else {
  document.addEventListener("DOMContentLoaded", init);
}
```

## The blog

The Material blog plugin turns `docs/blog/posts/` into a proper blog: archive, categories with their own pages, reading time, per-post metadata, tag pages, and an RSS feed from the `rss` plugin.

```yaml
plugins:
  - search
  - tags
  - blog:
      blog_dir: blog
      archive: true
      categories: true
      post_readtime: true
  - rss:
      match_path: "blog/posts/.*"
      date_from_meta:
        as_creation: "date"
        datetime_format: "%Y-%m-%d"
      categories:
        - categories
        - tags
```

Post metadata is just front matter:

```yaml
---
date: 2026-01-22
categories: [Meta, Tooling]
tags: [MkDocs, GitHub Pages]
authors: [0x3xp10i73r]
description: "One-line summary used for the post card and search results."
---
```

Keeping the blog in the same repository as the notes means one search box, one theme, one build, and no second place to forget to update.

## GitBook compatibility

The repository also contains a `.gitbook.yaml` and a `SUMMARY.md`, so the same Markdown tree can be imported into GitBook if I ever want that view for a specific audience:

```yaml
root: ./docs

structure:
  readme: index.md
  summary: SUMMARY.md
```

Be aware that Material-specific syntax does not render in GitBook. Content tabs (`=== "Tab"`), admonition syntax with custom titles, and the small HTML components degrade to plain readable text rather than breaking the page — acceptable, since MkDocs is the canonical version and gets checked on every change.

## Deployment

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - run: pip install -r requirements.txt
      - run: mkdocs gh-deploy --force
```

Locally it is three commands, and `mkdocs build` is what I actually rely on, because it fails loudly on broken internal links:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdocs serve                    # live reload while writing
mkdocs build                    # catch broken links before pushing
```

Pinning versions in `requirements.txt` is not optional. A theme release that changes plugin behaviour will otherwise break the build on a Monday morning when you are trying to publish a writeup.

## Things I got wrong

- I went through three themes in a year. The first was heavily customised — coloured badges, animated cards, a palette per section — and it made long pages harder to read. The second was stock Material with almost no CSS, which was honest but flat. What is here now is the third: black background, the Dracula palette, and nothing decorative that does not also carry meaning. No gradients, no blur, no animation. The colours do all the work.
- I used emoji as visual markers in headings. Fun for a week, actively annoying when scanning a sidebar with fifty entries.
- I put the navigation in top tabs first. With nine sections and sub-pages, the sidebar is the better layout: the whole tree is visible and nothing is hidden behind a hover state.
- I wrote `mkdocs.yml` navigation by hand, broke it, and learned that `mkdocs build` validates it. Run the build before you push, every time.
- I forgot to add `exclude_docs` for `SUMMARY.md`, which made MkDocs warn on every build about a page that exists but is not in the navigation. Warnings you get used to are warnings that hide real problems.
- I kept the checklists in a notes app for a year. Moving them into the site, where they sit next to the technique they describe, was the change that actually made me use them.

## Copying this

The configuration is meant to be reused. If you want your own version, the short version is:

```bash
git clone https://github.com/0x3xp10i73r/notes.git
cd notes
pip install -r requirements.txt
mkdocs serve
```

Then change `site_name`, `site_url` and `repo_url` in `mkdocs.yml`, replace the images in `docs/assets/images/`, and edit `DEFAULT_VARS` in `extra.js` to your usual lab values. The written content is mine; the structure and config you are welcome to take.

If you build something with it, send me a link. I read other people's note sites for the structure almost as much as for the content.
