#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | XFF Guard - aaPanel third-party plugin
# +-------------------------------------------------------------------
# | Stops X-Forwarded-For spoofing from bypassing the Nginx WAF.
# |
# | The problem: a client sends "X-Forwarded-For: 127.4.4.1".
# | Cloudflare *appends* the real IP, so the origin receives
# | "X-Forwarded-For: 127.4.4.1,203.0.113.50". A WAF that trusts the
# | left-most entry sees 127.4.4.1 (loopback = whitelisted) and lets
# | the attack through.
# |
# | The fix:
# |   1. ngx_http_realip_module: only trusted proxies (Cloudflare ranges,
# |      and loopback for Cloudflare Tunnel) may change $remote_addr, and
# |      only through CF-Connecting-IP (or a header you choose).
# |   2. A Lua rewrite-phase guard that overwrites X-Forwarded-For and
# |      X-Real-IP with the verified $remote_addr BEFORE the WAF's
# |      access phase runs, so the WAF can never read a spoofed value.
# |   3. Optional: log or block requests that carried a spoofed
# |      private/loopback address in X-Forwarded-For.
# +-------------------------------------------------------------------
import os
import sys
import json
import time
import shutil
import ipaddress
import subprocess

try:
    from urllib.request import urlopen
except ImportError:  # python 2 panels
    from urllib2 import urlopen

PANEL_PATH = '/www/server/panel'
if os.path.isdir(PANEL_PATH + '/class'):
    sys.path.insert(0, PANEL_PATH + '/class')
    os.chdir(PANEL_PATH)

PLUGIN_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PLUGIN_PATH, 'config.json')
BACKUP_PATH = os.path.join(PLUGIN_PATH, 'backup')

NGINX_BIN = '/www/server/nginx/sbin/nginx'
NGINX_CONF = '/www/server/nginx/conf/nginx.conf'
# Files in this directory are included inside the http{} block by aaPanel.
VHOST_NGINX = PANEL_PATH + '/vhost/nginx'
GUARD_CONF = VHOST_NGINX + '/0.xff_guard.conf'

BTWAF_PATH = '/www/server/btwaf'
BTWAF_SITE_JSON = BTWAF_PATH + '/site.json'

CF_V4_URL = 'https://www.cloudflare.com/ips-v4'
CF_V6_URL = 'https://www.cloudflare.com/ips-v6'

# Fallback list, used when cloudflare.com cannot be reached.
CF_DEFAULT = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
]
LOOPBACK = ['127.0.0.1', '::1']

ALLOWED_HEADERS = ['CF-Connecting-IP', 'True-Client-IP', 'X-Real-IP', 'X-Forwarded-For']

DEFAULT_CONFIG = {
    'enabled': False,
    'mode': 'cloudflare',          # cloudflare | custom | direct
    'trust_loopback': True,        # Cloudflare Tunnel / cloudflared runs on 127.0.0.1
    'real_ip_header': 'CF-Connecting-IP',
    'custom_proxies': [],
    'cf_ranges': CF_DEFAULT,
    'cf_updated': 0,
    'spoof_action': 'log',         # off | log | block
    'lua_guard': True,
    'last_apply': '',
    'last_result': '',
    'last_error': '',
}


def _ret(status, msg, data=None):
    r = {'status': status, 'msg': msg}
    if data is not None:
        r['data'] = data
    return r


def _run(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.communicate()[0]
    if not isinstance(out, str):
        out = out.decode('utf-8', 'ignore')
    return p.returncode, out


def _read(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        return f.read()


def _write(path, body):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        f.write(body)
    os.rename(tmp, path)


def _valid_cidr(value):
    """Strict validation so nothing but an IP/CIDR ever lands in nginx.conf."""
    try:
        ipaddress.ip_network(u'' + value.strip(), strict=False)
        return True
    except Exception:
        return False


class xff_guard_main:

    # ------------------------------------------------------------------ config
    def __load(self):
        conf = dict(DEFAULT_CONFIG)
        raw = _read(CONFIG_FILE)
        if raw:
            try:
                conf.update(json.loads(raw))
            except Exception:
                pass
        return conf

    def __save(self, conf):
        _write(CONFIG_FILE, json.dumps(conf, indent=2))

    # ------------------------------------------------------------- detection
    def __nginx_info(self):
        info = {'installed': os.path.exists(NGINX_BIN), 'realip': False, 'lua': False, 'version': ''}
        if not info['installed']:
            return info
        _, out = _run(NGINX_BIN + ' -V')
        info['realip'] = 'http_realip_module' in out
        info['lua'] = ('lua-nginx-module' in out) or ('lua_nginx_module' in out) or ('openresty' in out.lower())
        for line in out.splitlines():
            if 'nginx version' in line:
                info['version'] = line.split(':', 1)[-1].strip()
        return info

    def __foreign_realip(self):
        """Other http-level files already declaring real_ip_* cause 'duplicate' errors."""
        hits = []
        files = [NGINX_CONF]
        if os.path.isdir(VHOST_NGINX):
            files += [os.path.join(VHOST_NGINX, f) for f in sorted(os.listdir(VHOST_NGINX)) if f.endswith('.conf')]
        for f in files:
            if f == GUARD_CONF:
                continue
            body = _read(f) or ''
            if 'real_ip_header' not in body:
                continue
            # site vhosts set it inside server{}, which does not clash with http level
            if f != NGINX_CONF and 'server_name' in body:
                continue
            hits.append({'file': f, 'body': body[:4000], 'takeover': f != NGINX_CONF})
        return hits

    def __btwaf_sites(self):
        """List btwaf sites that read the client IP from a CDN header (the vulnerable path)."""
        raw = _read(BTWAF_SITE_JSON)
        if raw is None:
            return None
        try:
            sites = json.loads(raw)
        except Exception:
            return None
        result = []
        for name, cfg in sites.items():
            if not isinstance(cfg, dict):
                continue
            result.append({
                'name': name,
                'cdn': bool(cfg.get('cdn', False)),
                'cdn_header': cfg.get('cdn_header', []),
            })
        return result

    # -------------------------------------------------------- conf rendering
    def __trusted(self, conf):
        if conf['mode'] == 'cloudflare':
            nets = list(conf.get('cf_ranges') or CF_DEFAULT)
        elif conf['mode'] == 'custom':
            nets = list(conf.get('custom_proxies') or [])
        else:
            nets = []
        if conf['mode'] != 'direct' and conf.get('trust_loopback'):
            nets += LOOPBACK
        seen, out = set(), []
        for n in nets:
            n = n.strip()
            if n and n not in seen and _valid_cidr(n):
                seen.add(n)
                out.append(n)
        return out

    def __lua_block(self, conf):
        action = conf.get('spoof_action', 'log')
        return r'''
# Rewrite phase runs before the WAF access phase: the WAF only ever sees
# the verified client address in X-Forwarded-For / X-Real-IP.
rewrite_by_lua_block {
    local real = ngx.var.remote_addr
    local raw = ngx.req.get_headers()["x-forwarded-for"]
    if type(raw) == "table" then raw = table.concat(raw, ",") end

    local action = "%s"
    if raw and action ~= "off" then
        local function internal(ip)
            if ip == "::1" or ip:find("^[fF][cCdD]") or ip:find("^[fF][eE]80") then return true end
            local a, b = ip:match("^(%%d+)%%.(%%d+)%%.%%d+%%.%%d+$")
            a, b = tonumber(a), tonumber(b)
            if not a then return false end
            return a == 127 or a == 10 or a == 0 or (a == 169 and b == 254)
                or (a == 192 and b == 168) or (a == 172 and b >= 16 and b <= 31)
                or (a == 100 and b >= 64 and b <= 127)
        end
        for ip in raw:gmatch("[^,%%s]+") do
            if ip ~= real and internal(ip) then
                ngx.log(ngx.WARN, "[xff_guard] spoofed X-Forwarded-For '", raw,
                        "' from ", real, " ", ngx.var.request_method, " ", ngx.var.request_uri)
                if action == "block" then
                    return ngx.exit(403)
                end
                break
            end
        end
    end

    ngx.req.set_header("X-Forwarded-For", real)
    ngx.req.set_header("X-Real-IP", real)
}
''' % action

    def __render(self, conf, with_lua, with_realip=True):
        lines = [
            '# Managed by the XFF Guard aaPanel plugin. Do not edit by hand:',
            '# changes are overwritten on the next "Apply".',
            '# Generated: ' + time.strftime('%Y-%m-%d %H:%M:%S'),
        ]
        trusted = self.__trusted(conf)
        if with_realip and conf['mode'] != 'direct' and trusted:
            header = conf.get('real_ip_header', 'CF-Connecting-IP')
            if header not in ALLOWED_HEADERS:
                header = 'CF-Connecting-IP'
            lines.append('')
            lines.append('# Only these proxies may set the client address.')
            for n in trusted:
                lines.append('set_real_ip_from %s;' % n)
            lines.append('real_ip_header %s;' % header)
            # recursive only matters for the multi-value X-Forwarded-For header:
            # it then walks right-to-left skipping trusted proxies, never trusting the left-most value.
            lines.append('real_ip_recursive %s;' % ('on' if header == 'X-Forwarded-For' else 'off'))
        if with_lua:
            lines.append(self.__lua_block(conf))
        return '\n'.join(lines) + '\n'

    # ---------------------------------------------------------- nginx control
    def __nginx_test(self):
        code, out = _run('%s -t -c %s' % (NGINX_BIN, NGINX_CONF))
        return code == 0, out

    def __nginx_reload(self):
        if os.path.exists('/etc/init.d/nginx'):
            return _run('/etc/init.d/nginx reload')
        return _run('%s -s reload' % NGINX_BIN)

    def __deploy(self, conf):
        """
        Write the guard file and test it. Tries, in order:
          realip + Lua  ->  realip only  ->  Lua only (realip already declared elsewhere)
        Rolls back to the previous file if every variant fails.
        """
        old = _read(GUARD_CONF)

        # If nginx is already broken without our file, say so instead of blaming the plugin.
        if old is not None:
            os.remove(GUARD_CONF)
        ok, out = self.__nginx_test()
        if not ok:
            if old is not None:
                _write(GUARD_CONF, old)
            return False, ('nginx -t already fails WITHOUT XFF Guard, fix this first:\n' + out)

        info = self.__nginx_info()
        want_lua = bool(conf.get('lua_guard') and info['lua'])
        attempts = []
        if want_lua:
            attempts.append((True, True, 'realip + Lua header guard'))
        attempts.append((False, True, 'realip only'))
        if want_lua:
            attempts.append((True, False, 'Lua header guard only (real_ip_* is already set elsewhere)'))

        errors = []
        for with_lua, with_realip, note in attempts:
            _write(GUARD_CONF, self.__render(conf, with_lua, with_realip))
            ok, out = self.__nginx_test()
            if ok:
                self.__nginx_reload()
                if conf.get('lua_guard') and not with_lua:
                    note += ' (Lua guard skipped: %s)' % ('nginx has no Lua module' if not info['lua']
                                                          else 'conflicts with another http-level rewrite_by_lua')
                return True, note
            errors.append('[%s]\n%s' % (note, out.strip()))
        if old is None:
            os.remove(GUARD_CONF)
        else:
            _write(GUARD_CONF, old)
        return False, '\n\n'.join(errors)

    # ============================================================ panel API
    def get_status(self, get):
        conf = self.__load()
        info = self.__nginx_info()
        sites = self.__btwaf_sites()
        return _ret(True, 'ok', {
            'config': conf,
            'nginx': info,
            'active': os.path.exists(GUARD_CONF),
            'conf_preview': _read(GUARD_CONF) or '',
            'trusted_count': len(self.__trusted(conf)),
            'foreign_realip': self.__foreign_realip(),
            'btwaf_installed': os.path.isdir(BTWAF_PATH),
            'btwaf_sites': sites,
            'vulnerable_sites': [s['name'] for s in (sites or []) if s['cdn']],
        })

    def save_config(self, get):
        conf = self.__load()
        mode = getattr(get, 'mode', conf['mode'])
        if mode not in ('cloudflare', 'custom', 'direct'):
            return _ret(False, 'Invalid mode')
        header = getattr(get, 'real_ip_header', conf['real_ip_header'])
        if header not in ALLOWED_HEADERS:
            return _ret(False, 'Invalid real IP header')
        action = getattr(get, 'spoof_action', conf['spoof_action'])
        if action not in ('off', 'log', 'block'):
            return _ret(False, 'Invalid spoof action')

        proxies = []
        raw = getattr(get, 'custom_proxies', None)
        if raw is not None:
            for item in raw.replace(',', '\n').splitlines():
                item = item.strip()
                if not item:
                    continue
                if not _valid_cidr(item):
                    return _ret(False, 'Invalid IP/CIDR: %s' % item)
                proxies.append(item)
            conf['custom_proxies'] = proxies
        if mode == 'custom' and not conf['custom_proxies']:
            return _ret(False, 'Custom mode needs at least one trusted proxy IP/CIDR')

        conf['mode'] = mode
        conf['real_ip_header'] = header
        conf['spoof_action'] = action
        conf['trust_loopback'] = str(getattr(get, 'trust_loopback', conf['trust_loopback'])).lower() in ('1', 'true', 'on')
        conf['lua_guard'] = str(getattr(get, 'lua_guard', conf['lua_guard'])).lower() in ('1', 'true', 'on')
        self.__save(conf)
        if conf['enabled']:
            return self.apply(get)
        return _ret(True, 'Settings saved')

    def update_cloudflare(self, get):
        nets = []
        try:
            for url in (CF_V4_URL, CF_V6_URL):
                body = urlopen(url, timeout=10).read()
                if not isinstance(body, str):
                    body = body.decode('utf-8', 'ignore')
                for line in body.splitlines():
                    line = line.strip()
                    if line and _valid_cidr(line):
                        nets.append(line)
        except Exception as e:
            return _ret(False, 'Could not download Cloudflare ranges: %s' % e)
        if len(nets) < 10:
            return _ret(False, 'Cloudflare returned an unexpected list, kept the current ranges')
        conf = self.__load()
        conf['cf_ranges'] = nets
        conf['cf_updated'] = int(time.time())
        self.__save(conf)
        if conf['enabled']:
            ok, note = self.__deploy(conf)
            if not ok:
                return _ret(False, 'Ranges updated but nginx test failed:\n' + note)
        return _ret(True, 'Updated %d Cloudflare ranges' % len(nets))

    def apply(self, get):
        info = self.__nginx_info()
        if not info['installed']:
            return _ret(False, 'Nginx is not installed')
        if not info['realip'] and self.__load()['mode'] != 'direct':
            return _ret(False, 'This nginx build has no http_realip_module')
        if not os.path.isdir(VHOST_NGINX):
            return _ret(False, 'Missing %s' % VHOST_NGINX)
        conf = self.__load()
        conf['enabled'] = True
        ok, note = self.__deploy(conf)
        conf['last_apply'] = time.strftime('%Y-%m-%d %H:%M:%S')
        conf['last_result'] = note if ok else 'FAILED'
        conf['last_error'] = '' if ok else note
        if not ok:
            conf['enabled'] = os.path.exists(GUARD_CONF)
            self.__save(conf)
            return _ret(False, 'nginx -t failed, changes rolled back:\n' + note)
        self.__save(conf)
        return _ret(True, 'Protection enabled: ' + note)

    def takeover(self, get):
        """
        Disable another http-level real-IP file (e.g. real_cdn_ip.conf) so XFF Guard
        can own real_ip_header. The file is renamed (nginx only includes *.conf) and
        copied to the plugin backup folder; "Disable" puts it back.
        """
        path = os.path.realpath(getattr(get, 'file', ''))
        if os.path.dirname(path) != os.path.realpath(VHOST_NGINX) or not path.endswith('.conf') \
                or path == os.path.realpath(GUARD_CONF) or not os.path.isfile(path):
            return _ret(False, 'Only files in %s can be taken over' % VHOST_NGINX)
        if not os.path.isdir(BACKUP_PATH):
            os.makedirs(BACKUP_PATH)
        shutil.copy2(path, os.path.join(BACKUP_PATH, '%s.%s' % (os.path.basename(path), time.strftime('%Y%m%d%H%M%S'))))
        disabled = path + '.xff_guard_off'
        os.rename(path, disabled)

        conf = self.__load()
        taken = conf.get('taken_over', [])
        if path not in taken:
            taken.append(path)
        conf['taken_over'] = taken
        self.__save(conf)

        r = self.apply(get)
        if not r['status']:
            os.rename(disabled, path)
            conf = self.__load()
            conf['taken_over'] = [p for p in conf.get('taken_over', []) if p != path]
            self.__save(conf)
            return _ret(False, 'Restored %s because apply failed:\n%s' % (path, r['msg']))
        return _ret(True, 'Disabled %s and %s' % (os.path.basename(path), r['msg']))

    def __restore_taken(self, conf):
        restored = []
        for path in conf.get('taken_over', []):
            if os.path.exists(path + '.xff_guard_off') and not os.path.exists(path):
                os.rename(path + '.xff_guard_off', path)
                restored.append(os.path.basename(path))
        conf['taken_over'] = []
        return restored

    def disable(self, get):
        conf = self.__load()
        conf['enabled'] = False
        restored = self.__restore_taken(conf)
        self.__save(conf)
        if os.path.exists(GUARD_CONF):
            os.remove(GUARD_CONF)
        ok, out = self.__nginx_test()
        if not ok:
            return _ret(False, 'Removed guard file but nginx -t failed:\n' + out)
        self.__nginx_reload()
        msg = 'Protection disabled'
        if restored:
            msg += '; restored ' + ', '.join(restored)
        return _ret(True, msg)

    def fix_btwaf(self, get):
        """
        btwaf 'CDN mode' reads the left-most X-Forwarded-For value as the client IP,
        which is exactly what the attacker controls. With realip active, $remote_addr
        is already the verified client, so CDN mode is turned off for every site.
        A timestamped backup of site.json is kept in the plugin folder.
        """
        if not os.path.exists(GUARD_CONF):
            return _ret(False, 'Enable protection first, otherwise the WAF would see the proxy IP')
        raw = _read(BTWAF_SITE_JSON)
        if raw is None:
            return _ret(False, 'btwaf site.json not found at %s' % BTWAF_SITE_JSON)
        try:
            sites = json.loads(raw)
        except Exception:
            return _ret(False, 'Could not parse btwaf site.json')
        if not os.path.isdir(BACKUP_PATH):
            os.makedirs(BACKUP_PATH)
        backup = os.path.join(BACKUP_PATH, 'site.json.%s' % time.strftime('%Y%m%d%H%M%S'))
        shutil.copy2(BTWAF_SITE_JSON, backup)
        changed = []
        for name, cfg in sites.items():
            if isinstance(cfg, dict) and cfg.get('cdn'):
                cfg['cdn'] = False
                changed.append(name)
        if not changed:
            return _ret(True, 'No btwaf site uses CDN header mode, nothing to change')
        _write(BTWAF_SITE_JSON, json.dumps(sites))
        self.__nginx_reload()
        return _ret(True, 'Disabled CDN header mode for: %s (backup: %s)' % (', '.join(changed), backup))

    def get_logs(self, get):
        log = '/www/wwwlogs/nginx_error.log'
        if not os.path.exists(log):
            return _ret(True, 'ok', [])
        _, out = _run("tail -n 5000 %s | grep '\\[xff_guard\\]' | tail -n 100" % log)
        return _ret(True, 'ok', [l for l in out.splitlines() if l.strip()][::-1])

    def preview(self, get):
        conf = self.__load()
        info = self.__nginx_info()
        return _ret(True, 'ok', self.__render(conf, bool(conf.get('lua_guard') and info['lua'])))
