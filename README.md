# XFF Guard (aaPanel third-party plugin)

Fixes X-Forwarded-For spoofing on aaPanel nginx. Works on **aaPanel Free**
(no WAF needed) and with the **Pro Nginx WAF** (btwaf).

## The bypass

```
POST /.env HTTP/1.1
cf-connecting-ip: 203.0.113.50
x-forwarded-for: 127.4.4.1,203.0.113.50
cf-warp-tag-id: ...            <- request arrived through Cloudflare Tunnel
```

The attacker sends `X-Forwarded-For: 127.4.4.1`. Cloudflare appends the real
address, so the origin gets `127.4.4.1,203.0.113.50`. Anything that trusts the
left-most value sees `127.4.4.1`, a loopback address that is usually trusted:
the Pro WAF's CDN mode, PHP apps reading `$_SERVER['HTTP_X_FORWARDED_FOR']`,
admin IP whitelists, login rate limits. Through Cloudflare Tunnel,
`$remote_addr` is `127.0.0.1` as well, so nginx never sees the real client.

## What the plugin does

1. Writes `/www/server/panel/vhost/nginx/0.xff_guard.conf` (http level) with
   `set_real_ip_from` for the trusted proxies only: the Cloudflare ranges,
   plus `127.0.0.1`/`::1` for cloudflared. It also sets
   `real_ip_header CF-Connecting-IP`. Nginx then puts the verified client
   in `$remote_addr`, so aaPanel's IP allow/deny rules, `limit_req` and the
   access logs see the real visitor. A direct visitor's spoofed header is ignored.
2. Replaces `X-Forwarded-For` and `X-Real-IP` with the verified IP, using one
   of two engines (picked automatically):
   - **Lua engine**, when nginx has the Lua module: a `rewrite_by_lua_block`
     that runs before the WAF and the app.
   - **Native engine**, plain nginx, for aaPanel Free or any nginx without Lua:
     - adds two `fastcgi_param` lines to `fastcgi.conf`, so PHP gets the
       verified IP in `HTTP_X_FORWARDED_FOR` / `HTTP_X_REAL_IP`;
     - includes `/www/server/nginx/conf/xff_guard_server.conf` in every site's
       server block (marked `#XFF_GUARD`) to log or block spoofed requests.
3. Logs (or blocks with 403) requests whose XFF contained a spoofed private or
   loopback address. Native engine: `/www/wwwlogs/xff_guard_spoof.log`.
   Lua engine: lines tagged `[xff_guard]` in `nginx_error.log`.
4. **Reverse-proxy sites**: configs using `$proxy_add_x_forwarded_for` pass
   the spoofed chain to the backend. **Sanitize** swaps it for `$remote_addr`.
5. **WAF audit (Pro only)**: lists btwaf sites with "CDN" header mode on and
   can turn it off. Skipped automatically on aaPanel Free.

Every change runs `nginx -t` before the reload, and anything it modifies is
backed up to `plugin/xff_guard/backup/`. If a variant fails the test, the
plugin tries the next one; if all fail, it restores the previous state.
**Disable** and uninstalling undo every change.

## Install

1. aaPanel → App Store → **Third-party** → **Import plugin** → upload `xff_guard.zip`.
2. Open **XFF Guard**, choose **Cloudflare (proxy or Tunnel)**, and keep
   "Trust 127.0.0.1" ticked if you use cloudflared. Then click **Save & apply**.
3. If **Reverse-proxy sites** shows a red badge, click **Sanitize**.
4. Pro WAF only: on the **WAF audit** tab, click **Turn off CDN header mode on all sites**.
5. Native engine: after adding a new site in aaPanel, click **Save & apply**
   again so the new site gets the include too.

## Verify

```bash
curl -s -H 'X-Forwarded-For: 127.4.4.1' https://www.example.com/.env -o /dev/null -w '%{http_code}\n'
```

With **Block** selected, this returns `403`. With **Log only**, it shows up
on the **Spoof log** tab, and your access log and WAF log (Pro) show your real
IP, not `127.4.4.1`.

## Troubleshooting

### After updating: page errors, empty tabs or "older XFF Guard backend"

aaPanel keeps a plugin's Python code in memory. After importing a new zip,
the panel shows the new page but keeps running the old backend until it
restarts. Restart the panel, then reopen XFF Guard:

```bash
/etc/init.d/bt restart
```

### Apply fails: `"real_ip_header" directive is duplicate`

aaPanel's own CDN real-IP option writes
`/www/server/panel/vhost/nginx/real_cdn_ip.conf`, which already sets
`real_ip_header` at http level, so nginx rejects the second one from XFF Guard.
That file often trusts every IP (`set_real_ip_from 0.0.0.0/0;`), which is
itself enough to let a spoofed `X-Forwarded-For` through.

Move it out of the nginx include folder (this keeps a backup):

```bash
mv /www/server/panel/vhost/nginx/real_cdn_ip.conf /root/real_cdn_ip.conf.bak
```

Then open XFF Guard and click **Save & apply** again. The plugin's
**Replace it with XFF Guard** button does the same thing for you.

If aaPanel's CDN real-IP setting is still on, it may write the file again;
turn that setting off. To undo, click **Disable** in XFF Guard first (otherwise
the duplicate comes back), then move the backup back and reload nginx:

```bash
mv /root/real_cdn_ip.conf.bak /www/server/panel/vhost/nginx/real_cdn_ip.conf
```

```bash
/etc/init.d/nginx reload
```
