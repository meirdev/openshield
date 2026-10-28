// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightLinksValidator from "starlight-links-validator";

// GitHub Pages serves the site under the repository name; the workflow sets
// both variables. Locally the site is served at the root.
const site = process.env.SITE_URL ?? "http://localhost:4321";
const base = process.env.SITE_BASE ?? "/";

export default defineConfig({
  site,
  base,
  integrations: [
    starlight({
      title: "OpenShield",
      description:
        "A web application firewall built on Cloudflare Pingora and Wirefilter, with rules you can read.",
      logo: { src: "./src/assets/mark.svg", alt: "" },
      favicon: "/favicon.svg",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/meirdev/openshield",
        },
      ],
      customCss: [
        "@fontsource-variable/inter",
        "@fontsource-variable/space-grotesk",
        "@fontsource/ibm-plex-mono/400.css",
        "@fontsource/ibm-plex-mono/500.css",
        "./src/styles/theme.css",
        "./src/styles/landing.css",
      ],
      components: {
        Hero: "./src/components/Hero.astro",
        PageTitle: "./src/components/PageTitle.astro",
      },
      sidebar: [
        {
          label: "Getting started",
          items: [{ autogenerate: { directory: "getting-started" } }],
        },
        {
          label: "Configuration",
          items: [{ autogenerate: { directory: "configuration" } }],
        },
        { label: "Rules", items: [{ autogenerate: { directory: "rules" } }] },
        {
          label: "Protections",
          items: [{ autogenerate: { directory: "protections" } }],
        },
        {
          label: "Reference",
          items: [{ autogenerate: { directory: "reference" } }],
        },
        {
          label: "Operations",
          items: [{ autogenerate: { directory: "operations" } }],
        },
        { label: "Hosts", items: [{ autogenerate: { directory: "hosts" } }] },
      ],
      plugins: [starlightLinksValidator({ errorOnRelativeLinks: false })],
    }),
  ],
});
