# Cloudflare custom rule (interim php2shell mitigation)

Blocks `multipart/form-data` POSTs at the edge, except on upload endpoints and trusted networks. Not a fix; see [README.md](README.md) for when it fits.

**Where:** Dashboard → your zone → **Security → WAF → Custom rules → Create rule → Edit expression**.

```text
(http.request.method eq "POST"
 and any(lower(http.request.headers["content-type"][*])[*] contains "multipart/form-data")
 and not starts_with(http.request.uri.path, "/wp-admin/async-upload.php")
 and not starts_with(http.request.uri.path, "/wp-admin/media-new.php")
 and not starts_with(http.request.uri.path, "/wp-admin/update.php")
 and not starts_with(http.request.uri.path, "/wp-json/wp/v2/media")
 and not ip.src in {203.0.113.0/24})
```

**Action:** Block (or *Managed Challenge* if humans upload from unpredictable networks).

Notes:

- Replace the example network `203.0.113.0/24` with your office/VPN ranges, or remove that line.
- Adjust the paths to your application. For Moodle and other apps where many forms are multipart, prefer the network condition alone, or skip this rule and patch.
- Use **Security → Events** to watch what the rule blocks for the first hours, and keep the expression in *Log* mode first if your plan offers it.
- Also check whether Cloudflare's own managed rules cover php2shell on your plan and enable them; they complement, not replace, this rule.
- Cloudflare only protects traffic that goes through it. Make sure the origin is not reachable directly (firewall the origin to Cloudflare IP ranges), otherwise attackers bypass the edge.
