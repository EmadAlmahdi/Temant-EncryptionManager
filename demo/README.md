# Temant Package Demos

A React app for interactively demoing Temant PHP packages in a browser. Today it only demos
`temant/encryption-manager`, but the shell (sidebar + package registry) is built to grow: adding
a future package is a new entry in `web/src/packages/registry.tsx`, not a restructure.

```
demo/
  api/      PHP JSON API — thin glue between the browser and the actual package code
  web/      React + TypeScript + Tailwind frontend (Vite)
  apache/   Apache vhost config for serving this (and future) demos from /var/www/temant
```

The frontend never talks to package code directly — it calls the PHP API, which is the real
package running server-side. That's the point of the demo: it's exercising the actual library,
not a JS reimplementation of it.

Each package demo is mounted at its own subpath rather than the domain root (e.g.
`/encryption-manager/`), since `/var/www/temant` hosts demos for multiple Temant packages side
by side. `demo/web/vite.config.ts` sets this via Vite's `base` option, and `demo/web/src/lib/api.ts`
derives the API's URL from that same base — so the frontend keeps working unmodified no matter
where it's aliased.

## Running locally (dev servers)

From the repository root, make sure Composer dependencies are installed:

```bash
composer install
```

Then, in two terminals:

```bash
# Terminal 1 — PHP API on :8000. The -d flags raise the upload limit for the file/streamed-file
# demos — demo/api/.user.ini does the same thing automatically under PHP-FPM, but the built-in
# `php -S` server doesn't read .user.ini.
php -d upload_max_filesize=12M -d post_max_size=12M -S 127.0.0.1:8000 -t demo/api

# Terminal 2 — Vite dev server on :5173, proxies <base>api/* to :8000
cd demo/web
npm install
npm run dev
```

Open **`http://localhost:5173/encryption-manager/`** (note the path — the app is mounted at its
production subpath even in dev, not at `/`). The dev proxy keeps `/encryption-manager/api/*`
requests same-origin from the browser's point of view, so the session cookie the API uses to keep
a stable per-visitor encryption key works without any CORS setup.

## Production build

```bash
cd demo/web
npm run build   # outputs demo/web/dist
```

## Serving via Apache

`demo/apache/temant.conf` is a ready-to-use vhost that serves the whole `/var/www/temant`
directory (all Temant-* repos) and aliases this demo's build + API under `/encryption-manager/`.
Install it with:

```bash
sudo cp demo/apache/temant.conf /etc/apache2/sites-available/temant.conf
sudo a2ensite temant.conf
sudo systemctl reload apache2
echo "127.0.0.1 temant.local" | sudo tee -a /etc/hosts
```

Then visit `http://temant.local/encryption-manager/`. PHP is handled by whatever
`php-fpm`/`proxy_fcgi` config already applies server-wide — the vhost itself only needs
`Alias`/`Directory` blocks, no PHP handler directives.

Rebuild the frontend after any change (`npm run build` in `demo/web`) — Apache serves the static
`dist/` output directly, there's no dev server involved in this path.

## Adding a new package demo

1. Add the new package as a Composer dependency (or path repository) so its classes are
   autoloadable from `demo/api/bootstrap.php`.
2. Add PHP endpoints for it under `demo/api/` (following the pattern in `encrypt.php`/`decrypt.php`).
3. Add a `web/src/packages/<package-name>/` folder with a demo component, built from the shared
   UI kit in `web/src/components/ui/`.
4. Register it in `web/src/packages/registry.tsx`. It'll appear in the sidebar automatically.
5. Give it its own subpath (mirroring `/encryption-manager/`) in `demo/apache/temant.conf`.
