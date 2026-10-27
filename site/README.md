# Site

The documentation site, built with [Astro Starlight](https://starlight.astro.build) and published to GitHub Pages by `.github/workflows/site.yml` on every push to `main` that touches `site/`.

The documentation is written here, in `src/content/docs/`, one Markdown file per page with a `title` and `description` in its front matter; the sidebar groups follow the directories. `index.mdx` is the landing page, rendered by `src/components/Hero.astro` and `Landing.astro`. `PageTitle.astro` adds article breadcrumbs and descriptions. Other splash pages retain their own titles and actions; a `./` hero action returns to the site's base URL, including on nested 404 paths.

The field-guide design lives in `src/styles/theme.css` (shared light/dark themes and article layouts) and `src/styles/landing.css` (responsive home page). The home page's rule switcher shows illustrative excerpts and outcomes, not a running firewall; update its examples and documentation links together in `Landing.astro`. Fonts are bundled locally, and the request-flow illustration is inline SVG with reduced-motion support.

```bash
bun install
bun run dev      # http://localhost:4321/
bun run build    # static site in dist/, with internal links validated
```

Keep Node.js available on `PATH` when running Astro. A successful build ends with search indexing, internal-link validation, and `Complete!`; a build that stops at Pagefind has not finished. You can also run `node node_modules/astro/bin/astro.mjs build` directly.

`SITE_URL` and `SITE_BASE` set the deployed address; the workflow derives them from the repository name.
