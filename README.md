# 0x3xp10i73r — Offensive Security Notes

A personal notes site for authorized penetration testing, red team work and bug bounty hunting: web application testing, Active Directory, privilege escalation, cloud and mobile, plus a blog for longer writeups.

Built with [MkDocs](https://www.mkdocs.org/) and the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) theme. Navigation is a single left sidebar (no top tabs) with grouped section labels. The look uses Dracula's charcoal `#282a36` base with darker code surfaces, hairline borders, and Dracula's colours for text, links and syntax highlighting. Dark only — there is no light mode.

Sections:

- Recon
- Web and Bug Bounty
- Web Application Pentesting
- Active Directory
- Red Team
- Privilege Escalation
- Android
- Cloud
- Checklists
- Blog

## The Android section

`docs/android/` is a self-contained set of pages, written up from a 40-page notes dump:

| Page | Covers |
| :--- | :--- |
| `index.md` | OWASP Mobile Top 10, app types, APK structure and signing, architecture, components, manifest attributes |
| `setup-adb.md` | Device and emulator setup, ADB commands, wireless ADB, backups, package handling, MobSF |
| `proxy-certificates.md` | Burp CA into the system store, proxy configuration, and why interception fails |
| `static-analysis.md` | Hardcoded secrets, weak crypto, hybrid bundles, obfuscation, native libraries, Firebase |
| `dynamic-analysis.md` | Storage, logs, memory, root and emulator detection, pinning signals |
| `checklist.md` | The 23-item testing checklist with the command that proves each item |
| `frida.md` | Server setup, hook template, tracing, codeshare scripts |
| `glossary.md` | Android and tooling terms |
| `tools.md` | Tool table, helper commands, references |
| `ios-cross-platform.md` | iOS, Flutter, React Native and Cordova |

Code blocks follow a consistent convention across the vault: executable input is separated from sample output, related commands are grouped by phase, non-obvious flags and cleanup steps are commented, and the prose explains how to interpret the result.

## Page design

| Piece | Where |
| :--- | :--- |
| Cover image on every page | `overrides/main.html` picks a default from the page's section; a page overrides it with `cover:` front matter, or sets `cover: false` |
| Cover artwork | `docs/assets/images/cover-*.jpg` (1584x396, LinkedIn profile header proportions) |
| Reading width | `.md-grid { max-width: 68rem }` in `extra.css` |
| Heading anchors | Hidden until you hover a heading |
| Sidebar tree | Three levels: section label, collapsible sub-group, pages behind a hairline |

Covers are resolved per page, not copied into each file:

```yaml
# docs/recon/index.md inherits assets/images/cover-network.jpg
---
title: "Recon"
cover: assets/images/cover-ink.jpg   # optional, overrides the section default
---
```

The blog index and blog posts use an inline image with the `page-cover-img` class instead, because the blog template replaces the content block the override hooks into. Excerpts on `/blog/` hide covers via CSS so the list stays a list.

## How the look is put together

| Piece | Where |
| :--- | :--- |
| Palette overrides, component colours | `docs/assets/stylesheets/extra.css` — the variables at the top |
| Site logo, favicon, blog author avatar | `docs/assets/images/logo.svg`, `favicon.svg`, `avatar.svg` |
| Fonts | `mkdocs.yml` — `theme.font` (Inter for text, JetBrains Mono for code) |

`extra.css` sets Material's own variables rather than restyling components, so the theme keeps working normally:

```css
[data-md-color-scheme="slate"] {
  --md-default-bg-color: #000000;      /* AMOLED */
  --md-typeset-a-color: #bd93f9;       /* Dracula purple links */
  --md-accent-fg-color: #ff79c6;       /* Dracula pink */
  --md-code-bg-color: #191a21;
  --md-code-hl-keyword-color: #ff79c6;
  --md-code-hl-string-color: #f1fa8c;
  --md-code-hl-function-color: #50fa7b;
  --md-code-hl-comment-color: #6272a4;
}
```

The twelve Material admonition types (`note`, `tip`, `warning`, `danger`, …) are each mapped to the nearest Dracula colour through a single `--adm` variable per type.

## Two features worth knowing about


**Command variables.** Any page whose code blocks contain a placeholder gets a small box above the first block. Pages with commands but nothing to substitute — the Android pages, for example — get no box. The values you enter there (`<TARGET_IP>`, `<DOMAIN>`, `<DC_IP>`, `<LHOST>`, `<LPORT>`, `<USER>`) replace those placeholders in every command on the page, including what the copy button puts on your clipboard, and they are remembered in your browser.

**Interactive checklists.** The checkbox items on the checklist pages are clickable and their state is stored per page in `localStorage`, with a counter above the list and a reset button.

Both live in `docs/assets/javascripts/extra.js`. The styling for them is in `docs/assets/stylesheets/extra.css`. Both are skipped on the blog index and on post pages, where they would otherwise pick up code blocks and list items from post excerpts.

Blog posts are split with a `<!-- more -->` marker: everything above it becomes the excerpt on `/blog/`, and the rest stays on the post page.

## Running it locally

```bash
# Create and activate an isolated environment for the documentation toolchain.
python3 -m venv .venv
source .venv/bin/activate

# Install the project dependencies declared in requirements.txt.
pip install -r requirements.txt

# Start a live-reloading server on all interfaces for local or preview use.
mkdocs serve -a 0.0.0.0:8000

# Build the static site and catch broken links before publishing.
mkdocs build
```

## Deploying

The included GitHub Actions workflow (`.github/workflows/deploy.yml`) builds the site and publishes it to the `gh-pages` branch on every push to `main`. Enable GitHub Pages for the repository and point it at that branch.

Manually, from a clone:

```bash
# Build the site and publish the generated output to the configured Pages branch.
# Run this only from the repository and only when the deployment target is correct.
mkdocs gh-deploy --force
```

GitBook sync is also possible: `.gitbook.yaml` and `docs/SUMMARY.md` are included, and the `SUMMARY.md` mirrors the navigation in `mkdocs.yml`. Material-specific syntax degrades to plain text in GitBook, so MkDocs remains the canonical version.

## Making it yours

| What | Where |
| :--- | :--- |
| Site name, description, copyright | `mkdocs.yml` |
| Domain and repository links | `mkdocs.yml` — `site_url`, `repo_url`, `repo_name`, `edit_uri` |
| Social links | `mkdocs.yml` — `extra.social` |
| Navigation and section order | `mkdocs.yml` — `nav` (mirror changes in `docs/SUMMARY.md`) |
| Colour scheme | `mkdocs.yml` — `theme.palette`, plus the variables at the top of `extra.css` |
| Dracula colour values | The `--d-*` variables at the top of `extra.css` |
| Default values in the command box | `docs/assets/javascripts/extra.js` — `DEFAULT_VARS` |
| Author name and avatar for blog posts | `docs/blog/.authors.yml` |
| Images, covers | `docs/assets/images/` |
| Which cover a section uses | The `covers` map in `overrides/main.html` |
| Example blog posts | `docs/blog/posts/` |

To publish a rebuilt copy:

```bash
# Build the static site into ./site and fail early if the Markdown is invalid.
mkdocs build

# Package the project directory from its parent when a portable archive is needed.
cd ..
zip -r notes-site.zip <project-folder>
```

## Content warning

Everything here is written for authorized security testing, red team engagements, CTFs and lab environments. Do not use any of it against systems you do not own or have explicit written permission to test.
