---
title: "About"
description: "About this site, its author, and how it is built."
---

# About

I go by **0x3xp10i73r**. I work in offensive security — web application testing, internal network and Active Directory assessments, and red team engagements — with bug bounty hunting on the side.

This site is my notebook. I started keeping notes publicly for three reasons: I was tired of solving the same problem twice, writing something down properly forces me to actually understand it, and other people's notes have saved me hundreds of hours, so this is the version of that I can give back.

A few things about the content:

- Everything technical here is either something I have run myself, something I have verified in a lab, or something I have clearly flagged as untested reading. If I am not sure, I say so in the page.
- The notes assume you already understand the basics. They are written for someone mid-engagement who needs the exact flag, the exact path, or the detection signal — not as a beginner course.
- Tooling ages fast. If a command no longer works with the current version of a tool, tell me and I will fix it.

## Contact

- GitHub: [0x3xp10i73r](https://github.com/0x3xp10i73r)
- X: [@0x3xp10i73r](https://x.com/0x3xp10i73r)
- Email: meghantashi.h4cks@gmail.com

Corrections, disagreements and additions are all welcome. If you are sending a fix, a link to the documentation or the commit that changed the behaviour is worth more than a description.

## How this site is built

Plain Markdown in a Git repository, built with [MkDocs](https://www.mkdocs.org/) and the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) theme, deployed to GitHub Pages by a GitHub Actions workflow on every push to `main`. The small amount of custom CSS and JavaScript that powers the command variable box and the checklists is in `docs/assets/`, and everything is deliberately dependency-light so the site still builds in a few years.

A `.gitbook.yaml` and a `SUMMARY.md` are included as well, so the same source can be imported into GitBook if you prefer that reading experience. MkDocs remains the canonical version.

If you want to run it locally or use it as a starting point for your own notes:

```bash
git clone https://github.com/0x3xp10i73r/notes.git
cd notes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdocs serve
```

The site is licensed for reuse of the *structure and configuration*. The written content is mine — quote it, link it, learn from it, but do not republish it as your own.

## A note on credibility

I do not claim to be an authority on any of this. Some of what is on this site will be wrong, some of it will be opinionated in ways you disagree with, and the field moves fast enough that parts of it will be dated by the time you read them. Treat it as one practitioner's notebook, cross-check it against primary sources, and test things in a lab before you trust them in production.
