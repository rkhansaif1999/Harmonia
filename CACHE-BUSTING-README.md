# Cache Busting — What was added & how to use it

Your visitors were seeing old versions of the site because browsers were
caching the HTML, CSS, and JS files. Three layers were added to fix this,
nothing else was touched:

## 1. HTML meta tags (in every .html file)
Right after `<meta charset="UTF-8">`, these lines were added:

```html
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
```

This tells browsers to always check with the server before showing a page
from cache, so page edits (text, sections, layout) show up immediately.

## 2. Versioned CSS/JS links
Every `style.css` and `script.js` reference now includes a version query
string:

```html
<link rel="stylesheet" href="style.css?v=20260720">
<script src="script.js?v=20260720"></script>
```

Browsers cache `style.css` and `script.js` aggressively by default. Because
the URL now includes `?v=20260720`, browsers treat it as a brand-new file.

**Whenever you edit `style.css` or `script.js` in the future, update the
`?v=...` number in every HTML file (e.g. `?v=20260721`) so returning
visitors immediately get the new version instead of an old cached copy.**
You can do this with a quick find-and-replace across all `.html` files.

## 3. Server-level cache headers (backup layer)
A `_headers` file was added at the root of the site. This is read
automatically by **Cloudflare Pages** (your hosting provider) and tells
Cloudflare's edge to send `Cache-Control: no-cache` for HTML files, so even
a browser that ignores the meta tags will still revalidate with the server
before showing a cached page.

(An `.htaccess` file was previously included as a fallback for Apache/cPanel
hosting, but since your site runs on Cloudflare Pages — which doesn't read
`.htaccess` — it was removed as dead weight.)

## Nothing else was changed
No existing content, layout, scripts, or styles were modified — only these
cache-busting additions were made.
