# XFF Guard (aaPanel third-party plugin)

Fixes the X-Forwarded-For bypass of the aaPanel Nginx WAF (btwaf).

## The bypass

```
POST /.env HTTP/1.1
cf-connecting-ip: 203.0.113.50
x-forwarded-for: 127.4.4.1,203.0.113.50
cf-warp-tag-id: ...            <- request arrived through Cloudflare Tunnel
```

The attacker sends `X-Forwarded-For: 127.4.4.1`. Cloudflare appends the real
address, so the origin gets `127.4.4.1,203.0.113.50`. The WAF's CDN mode takes
the left-most value, so it sees `127.4.4.1`: a loopback address that is
whitelisted. Through Cloudflare Tunnel, `$remote_addr` is `127.0.0.1`
as well, so the WAF never sees the real client.

## What the plugin does

1. Writes `/www/server/panel/vhost/nginx/0.xff_guard.conf` (http level) with
   `set_real_ip_from` for the trusted proxies only: the Cloudflare ranges,
   plus `127.0.0.1`/`::1` for cloudflared. It also sets
   `real_ip_header CF-Connecting-IP`. Nginx then puts the verified client
   in `$remote_addr`. A direct visitor's spoofed header is ignored.
2. Adds a Lua `rewrite_by_lua_block`. It runs before the WAF's access
   phase and overwrites `X-Forwarded-For` and `X-Real-IP` with the
   verified IP, so the WAF and the backend apps can't read the spoofed
   value.
3. Logs (or blocks with 403) requests whose XFF contained a spoofed private or
   loopback address. Tag in `nginx_error.log`: `[xff_guard]`.
4. **WAF audit**: lists btwaf sites with "CDN" header mode on and can turn it
   off. It backs up `site.json` to `plugin/xff_guard/backup/` first.

Every change runs `nginx -t` before the reload. If the Lua guard conflicts
with another http-level `rewrite_by_lua`, the plugin falls back to realip
only. If the test still fails, it restores the previous file.

## Install

1. aaPanel → App Store → **Third-party** → **Import plugin** → upload `xff_guard.zip`.
2. Open **XFF Guard**, choose **Cloudflare (proxy or Tunnel)**, and keep
   "Trust 127.0.0.1" ticked if you use cloudflared. Then click **Save & apply**.
3. On the **WAF audit** tab, click **Turn off CDN header mode on all sites**.

## Verify

```bash
curl -s -H 'X-Forwarded-For: 127.4.4.1' https://www.example.com/.env -o /dev/null -w '%{http_code}\n'
```

This should now be blocked by the WAF (or by XFF Guard, if set to Block).
In the WAF log, the client IP should be your real IP, not `127.4.4.1`.

## Troubleshooting

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
