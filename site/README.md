# Site

The documentation site, built with [Astro Starlight](https://starlight.astro.build) and published to GitHub Pages by `.github/workflows/site.yml` on every push to `main` that touches `site/`.

The documentation is written here, in `src/content/docs/`, one Markdown file per page with a `title` and `description` in its front matter; the sidebar groups follow the directories. `index.mdx` is the landing page, rendered by `src/components/Hero.astro` and `Landing.astro`; the theme lives in `src/styles/`.

```bash
bun install
bun run dev      # http://localhost:4321/
bun run build    # static site in dist/, with internal links validated
```

`SITE_URL` and `SITE_BASE` set the deployed address; the workflow derives them from the repository name.
