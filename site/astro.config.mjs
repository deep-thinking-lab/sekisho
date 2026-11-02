import { defineConfig } from 'astro/config';

export default defineConfig({
  site: (process.env.SEKISHO_SITE_URL || 'https://sekisho.sh').replace(/\/+$/, ''),
  output: 'static',
  build: { format: 'directory' },
});
