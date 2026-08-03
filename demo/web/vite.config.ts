import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The production Apache vhost (see /etc/apache2/sites-available/temant.conf) has no Alias
// directives — it just serves /var/www/temant as a plain DocumentRoot with directory indexing.
// So this app is reached at the physical path its `dist/` build lives at, and the PHP API (a
// sibling of web/, not nested under it) is reached at its own physical path alongside it.
const base = '/Temant-EncryptionManager/demo/web/dist/'
const apiBase = '/Temant-EncryptionManager/demo/api/'

// https://vite.dev/config/
export default defineConfig({
  base,
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // In dev, forward straight to the real Apache-hosted API so there's no need to run a
      // separate `php -S` server.
      [apiBase]: {
        target: 'https://temant',
        changeOrigin: true,
        secure: true,
      },
    },
  },
})