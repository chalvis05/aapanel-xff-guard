#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | XFF Guard - aaPanel third-party plugin
# +-------------------------------------------------------------------
# | Stops X-Forwarded-For spoofing. Works on aaPanel Free (no WAF) and
# | with the Pro Nginx WAF (btwaf).
# |
# | The problem: a client sends "X-Forwarded-For: 127.4.4.1".
# | Cloudflare *appends* the real IP, so the origin receives
# | "X-Forwarded-For: 127.4.4.1,203.0.113.50". Anything that trusts the
# | left-most entry (the Pro WAF, PHP apps, admin IP whitelists, rate
# | limits) sees 127.4.4.1 (loopback = trusted) and lets the attack through.
# |
# | The fix:
# |   1. ngx_http_realip_module: only trusted proxies (Cloudflare ranges,
# |      and loopback for Cloudflare Tunnel) may change $remote_addr, and
# |      only through CF-Connecting-IP (or a header you choose).
# |   2. X-Forwarded-For / X-Real-IP are replaced with the verified
# |      $remote_addr before the WAF or the app can read them:
# |        - "lua" engine: a rewrite_by_lua_block (needs nginx with Lua)
# |        - "native" engine: plain nginx, no Lua and no WAF needed:
# |          fastcgi.conf overrides the headers PHP sees, a per-site include
# |          logs/blocks spoofed requests.
# |   3. Optional: log or block requests that carried a spoofed
# |      private/loopback address in X-Forwarded-For.
# +-------------------------------------------------------------------
import io
import os
import re
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
NGINX_CONF_DIR = '/www/server/nginx/conf'
NGINX_CONF = NGINX_CONF_DIR + '/nginx.conf'
# Files in this directory are included inside the http{} block by aaPanel.
VHOST_NGINX = PANEL_PATH + '/vhost/nginx'
GUARD_CONF = VHOST_NGINX + '/0.xff_guard.conf'
PROXY_DIR = VHOST_NGINX + '/proxy'

# Native engine pieces. Kept outside the plugin folder so a missing plugin
# folder can never leave nginx pointing at a file that does not exist.
SERVER_SNIPPET = NGINX_CONF_DIR + '/xff_guard_server.conf'
FASTCGI_FILES = [NGINX_CONF_DIR + '/fastcgi.conf', NGINX_CONF_DIR + '/fastcgi_params']
MARK = '#XFF_GUARD'
SPOOF_LOG = '/www/wwwlogs/xff_guard_spoof.log'
ERROR_LOG = '/www/wwwlogs/nginx_error.log'

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

# Private, loopback, link-local and CGNAT addresses anywhere in X-Forwarded-For.
SPOOF_REGEX = (r'(^|[,\s])(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.'
               r'|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|::1|f[cd][0-9a-f]*:|fe80:)')

DEFAULT_CONFIG = {
    'enabled': False,
    'mode': 'cloudflare',          # cloudflare | custom | direct
    'trust_loopback': True,        # Cloudflare Tunnel / cloudflared runs on 127.0.0.1
    'real_ip_header': 'CF-Connecting-IP',
    'custom_proxies': [],
    'cf_ranges': CF_DEFAULT,
    'cf_updated': 0,
    'spoof_action': 'log',         # off | log | block
    'lua_guard': True,             # prefer the Lua engine when nginx has Lua
    'engine': '',                  # engine currently deployed: lua | native
    'taken_over': [],
    'proxy_patched': [],
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


# aaPanel configs carry Chinese comments and sometimes GBK bytes, and the panel
# may run under a non-UTF-8 locale. Read as UTF-8, round-trip any invalid bytes
# untouched (surrogateescape), and keep the file's own line endings.
_ENC_ERRORS = 'surrogateescape' if sys.version_info[0] >= 3 else 'ignore'


def _read(path):
    if not os.path.isfile(path):
        return None
    with io.open(path, 'r', encoding='utf-8', errors=_ENC_ERRORS, newline='') as f:
        return f.read()


def _write(path, body):
    tmp = path + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8', errors=_ENC_ERRORS, newline='') as f:
        f.write(body)
    if os.path.exists(path):
        shutil.copymode(path, tmp)
    getattr(os, 'replace', os.rename)(tmp, path)


def _valid_cidr(value):
    """Strict validation so nothing but an IP/CIDR ever lands in nginx.conf."""
    try:
        ipaddress.ip_network(u'' + value.strip(), strict=False)
        return True
    except Exception:
        return False


def _strip_marked(body):
    return ''.join(l for l in body.splitlines(True) if MARK not in l)


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

    def __btwaf_path(self):
        """site.json location differs between WAF versions."""
        if os.path.isfile(BTWAF_SITE_JSON):
            return BTWAF_SITE_JSON
        for root, dirs, names in os.walk(BTWAF_PATH):
            if root.count(os.sep) - BTWAF_PATH.count(os.sep) >= 2:
                del dirs[:]
            if 'site.json' in names:
                return os.path.join(root, 'site.json')
        return None

    def __btwaf_load(self):
        """
        Returns (path, data, entries, error). entries is a list of (name, cfg) where
        cfg is the live dict inside data, so changes to it can be saved back.
        Accepts {"site": {...}} and [{"name"/"siteName": "site", ...}] layouts.
        """
        path = self.__btwaf_path()
        if path is None:
            return None, None, [], 'site.json not found under %s' % BTWAF_PATH
        try:
            data = json.loads(_read(path) or '')
        except Exception as e:
            return path, None, [], 'Could not parse %s: %s' % (path, e)
        entries = []
        if isinstance(data, dict):
            entries = [(k, v) for k, v in data.items() if isinstance(v, dict)]
        elif isinstance(data, list):
            for i, v in enumerate(data):
                if isinstance(v, dict):
                    entries.append((v.get('name') or v.get('siteName') or v.get('site') or 'site #%d' % (i + 1), v))
        return path, data, entries, ''

    @staticmethod
    def __truthy(v):
        return v is True or (isinstance(v, (int, float)) and v != 0) or \
            (isinstance(v, str) and v.strip().lower() in ('1', 'true', 'on', 'yes', 'open'))

    def __btwaf_sites(self):
        """btwaf sites and whether they read the client IP from a CDN header (the vulnerable path)."""
        path, _, entries, error = self.__btwaf_load()
        sites = []
        for name, cfg in entries:
            header = cfg.get('cdn_header', [])
            sites.append({
                'name': name,
                'cdn': self.__truthy(cfg.get('cdn', False)),
                'cdn_header': header if isinstance(header, list) else [header],
            })
        return {'path': path, 'error': error, 'sites': sites}

    def __site_files(self):
        """aaPanel site vhosts: http-level *.conf files that contain a server block."""
        out = []
        if not os.path.isdir(VHOST_NGINX):
            return out
        for f in sorted(os.listdir(VHOST_NGINX)):
            path = os.path.join(VHOST_NGINX, f)
            if not f.endswith('.conf') or path == GUARD_CONF or not os.path.isfile(path):
                continue
            body = _read(path) or ''
            if re.search(r'^\s*server_name\b', body, re.M):
                out.append(path)
        return out

    def __proxy_files(self):
        """Config files that forward the client's own X-Forwarded-For chain to a backend."""
        files = list(self.__site_files())
        if os.path.isdir(PROXY_DIR):
            for root, _, names in os.walk(PROXY_DIR):
                files += [os.path.join(root, n) for n in names if n.endswith('.conf')]
        return [f for f in files if '$proxy_add_x_forwarded_for' in (_read(f) or '')]

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
                -- CRIT: aaPanel's nginx.conf only writes "error_log ... crit" and above
                ngx.log(ngx.CRIT, "[xff_guard] spoofed X-Forwarded-For '", raw,
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

    def __native_block(self):
        return '''
# Native engine (no Lua, no WAF): flags requests whose X-Forwarded-For
# carries a private/loopback address. Used by %s,
# which is included in every site's server block.
map $http_x_forwarded_for $xff_guard_spoof {
    default 0;
    "~*%s" 1;
}
log_format xff_guard '$time_local $remote_addr "$http_x_forwarded_for" $host "$request" $status';
''' % (SERVER_SNIPPET, SPOOF_REGEX)

    def __render(self, conf, engine, with_realip=True):
        lines = [
            '# Managed by the XFF Guard aaPanel plugin. Do not edit by hand:',
            '# changes are overwritten on the next "Apply".',
            '# Generated: ' + time.strftime('%Y-%m-%d %H:%M:%S') + '  engine: ' + engine,
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
        if engine == 'lua':
            lines.append(self.__lua_block(conf))
        else:
            lines.append(self.__native_block())
        return '\n'.join(lines) + '\n'

    def __render_snippet(self, conf):
        action = conf.get('spoof_action', 'log')
        lines = ['# Managed by XFF Guard. Included in each site server block.']
        if action != 'off':
            lines.append('access_log %s xff_guard if=$xff_guard_spoof;' % SPOOF_LOG)
        if action == 'block':
            lines.append('if ($xff_guard_spoof) { return 403; }')
        return '\n'.join(lines) + '\n'

    # ------------------------------------------------------- native engine
    def __set_native(self, on, conf=None):
        """Install or remove the per-site include and the fastcgi header override."""
        for path in self.__site_files():
            body = _read(path) or ''
            new = _strip_marked(body)
            if on:
                new = re.sub(r'^([ \t]*)server_name\b[^\n]*$',
                             lambda m: '%s\n%sinclude %s; %s' % (m.group(0), m.group(1), SERVER_SNIPPET, MARK),
                             new, flags=re.M)
            if new != body:
                _write(path, new)

        # PHP: an HTTP_* fastcgi_param replaces the client's request header,
        # so $_SERVER['HTTP_X_FORWARDED_FOR'] becomes the verified address.
        for path in FASTCGI_FILES:
            body = _read(path)
            if body is None:
                continue
            new = _strip_marked(body)
            if on:
                if not new.endswith('\n'):
                    new += '\n'
                new += ('fastcgi_param HTTP_X_FORWARDED_FOR $remote_addr; %s\n'
                        'fastcgi_param HTTP_X_REAL_IP $remote_addr; %s\n') % (MARK, MARK)
            if new != body:
                _write(path, new)

        if on:
            _write(SERVER_SNIPPET, self.__render_snippet(conf))
        elif os.path.exists(SERVER_SNIPPET):
            os.remove(SERVER_SNIPPET)

    # ---------------------------------------------------------- nginx control
    def __nginx_test(self):
        code, out = _run('%s -t -c %s' % (NGINX_BIN, NGINX_CONF))
        return code == 0, out

    def __nginx_reload(self):
        if os.path.exists('/etc/init.d/nginx'):
            return _run('/etc/init.d/nginx reload')
        return _run('%s -s reload' % NGINX_BIN)

    def __remove_guard(self):
        self.__set_native(False)
        if os.path.exists(GUARD_CONF):
            os.remove(GUARD_CONF)

    def __deploy(self, conf):
        """
        Write the guard and test it. Tries, in order:
          Lua engine: realip + Lua   -> (falls through to native)
          native:     realip + native
          Lua only / native only (real_ip_* already declared elsewhere)
        Restores the previous state if every variant fails.
        """
        old = _read(GUARD_CONF)
        old_engine = conf.get('engine', '')

        def restore():
            self.__remove_guard()
            if old is not None:
                if old_engine == 'native':
                    self.__set_native(True, conf)
                _write(GUARD_CONF, old)

        # If nginx is already broken without our files, say so instead of blaming the plugin.
        self.__remove_guard()
        ok, out = self.__nginx_test()
        if not ok:
            restore()
            return False, ('nginx -t already fails WITHOUT XFF Guard, fix this first:\n' + out)

        info = self.__nginx_info()
        want_lua = bool(conf.get('lua_guard') and info['lua'])
        attempts = []
        if want_lua:
            attempts.append(('lua', True, 'realip + Lua header guard'))
        attempts.append(('native', True, 'realip + native header guard'))
        if want_lua:
            attempts.append(('lua', False, 'Lua header guard only (real_ip_* is already set elsewhere)'))
        attempts.append(('native', False, 'native header guard only (real_ip_* is already set elsewhere)'))

        errors = []
        for engine, with_realip, note in attempts:
            self.__set_native(engine == 'native', conf)
            _write(GUARD_CONF, self.__render(conf, engine, with_realip))
            ok, out = self.__nginx_test()
            if ok:
                self.__nginx_reload()
                conf['engine'] = engine
                if engine == 'native':
                    note += ' on %d site(s)' % len(self.__site_files())
                    if conf.get('lua_guard') and not info['lua']:
                        note += ' (nginx has no Lua module)'
                return True, note
            errors.append('[%s]\n%s' % (note, out.strip()))
        restore()
        return False, '\n\n'.join(errors)

    # ============================================================ panel API
    def get_status(self, get):
        # Each section is isolated: one unreadable file must not blank the whole page.
        errors = []

        def safe(label, fn, default):
            try:
                return fn()
            except Exception as e:
                errors.append('%s: %s: %s' % (label, type(e).__name__, e))
                return default

        conf = safe('config', self.__load, dict(DEFAULT_CONFIG))
        info = safe('nginx', self.__nginx_info, {'installed': False, 'realip': False, 'lua': False, 'version': ''})
        btwaf_installed = os.path.isdir(BTWAF_PATH)
        waf = safe('WAF sites', self.__btwaf_sites, {'path': None, 'error': 'read failed', 'sites': []}) \
            if btwaf_installed else {'path': None, 'error': '', 'sites': []}
        site_files = safe('site configs', self.__site_files, [])
        return _ret(True, 'ok', {
            'config': conf,
            'nginx': info,
            'active': os.path.exists(GUARD_CONF),
            'conf_preview': safe('guard conf', lambda: _read(GUARD_CONF) or '', ''),
            'snippet_preview': safe('site snippet', lambda: _read(SERVER_SNIPPET) or '', ''),
            'trusted_count': safe('trusted', lambda: len(self.__trusted(conf)), 0),
            'foreign_realip': safe('real-IP scan', self.__foreign_realip, []),
            'btwaf_installed': btwaf_installed,
            'btwaf_path': waf['path'],
            'btwaf_error': waf['error'],
            'btwaf_sites': waf['sites'],
            'vulnerable_sites': [s['name'] for s in waf['sites'] if s['cdn']],
            'sites_total': len(site_files),
            'sites_guarded': safe('site coverage', lambda: len([f for f in site_files if MARK in (_read(f) or '')]), 0),
            'proxy_spoofable': safe('reverse-proxy scan', self.__proxy_files, []),
            'errors': errors,
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
            return self.apply(get)
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

    def sanitize_proxy(self, get):
        """
        Reverse-proxy sites pass "$proxy_add_x_forwarded_for" to the backend, which is
        the client's own (spoofable) X-Forwarded-For plus $remote_addr. Replace it with
        the verified $remote_addr. Every file is backed up; "Disable" restores them.
        """
        files = self.__proxy_files()
        if not files:
            return _ret(True, 'No reverse-proxy config forwards a spoofable X-Forwarded-For')
        dest = os.path.join(BACKUP_PATH, 'proxy')
        if not os.path.isdir(dest):
            os.makedirs(dest)
        conf = self.__load()
        patched = conf.get('proxy_patched', [])
        done = []
        stamp = time.strftime('%Y%m%d%H%M%S')
        for path in files:
            backup = os.path.join(dest, '%s.%s' % (re.sub(r'[^\w.-]+', '_', path.strip('/')), stamp))
            shutil.copy2(path, backup)
            _write(path, (_read(path) or '').replace('$proxy_add_x_forwarded_for', '$remote_addr'))
            done.append({'file': path, 'backup': backup})
        ok, out = self.__nginx_test()
        if not ok:
            for item in done:
                shutil.copy2(item['backup'], item['file'])
            return _ret(False, 'nginx -t failed, reverse-proxy configs restored:\n' + out)
        conf['proxy_patched'] = patched + done
        self.__save(conf)
        self.__nginx_reload()
        return _ret(True, 'Sanitized %d reverse-proxy config(s)' % len(done))

    def __restore_taken(self, conf):
        restored = []
        for path in conf.get('taken_over', []):
            if os.path.exists(path + '.xff_guard_off') and not os.path.exists(path):
                os.rename(path + '.xff_guard_off', path)
                restored.append(os.path.basename(path))
        conf['taken_over'] = []
        return restored

    def __restore_proxy(self, conf):
        restored = []
        # oldest backup per file wins: it is the original, pre-plugin version
        seen = set()
        for item in conf.get('proxy_patched', []):
            if item['file'] in seen or not os.path.exists(item['backup']):
                continue
            seen.add(item['file'])
            # the backup may hold native-engine include lines, which were removed with the guard
            _write(item['file'], _strip_marked(_read(item['backup']) or ''))
            restored.append(os.path.basename(item['file']))
        conf['proxy_patched'] = []
        return restored

    def disable(self, get):
        conf = self.__load()
        conf['enabled'] = False
        conf['engine'] = ''
        self.__remove_guard()
        restored = self.__restore_taken(conf) + self.__restore_proxy(conf)
        self.__save(conf)
        ok, out = self.__nginx_test()
        if not ok:
            return _ret(False, 'Removed XFF Guard but nginx -t failed:\n' + out)
        self.__nginx_reload()
        msg = 'Protection disabled'
        if restored:
            msg += '; restored ' + ', '.join(restored)
        return _ret(True, msg)

    def fix_btwaf(self, get):
        """
        Pro Nginx WAF only. btwaf 'CDN mode' reads the left-most X-Forwarded-For value
        as the client IP, which is exactly what the attacker controls. With realip active,
        $remote_addr is already the verified client, so CDN mode is turned off for every
        site. A timestamped backup of site.json is kept in the plugin folder.
        """
        if not os.path.exists(GUARD_CONF):
            return _ret(False, 'Enable protection first, otherwise the WAF would see the proxy IP')
        path, data, entries, error = self.__btwaf_load()
        if error:
            return _ret(False, error)
        changed = []
        for name, cfg in entries:
            v = cfg.get('cdn', False)
            if self.__truthy(v):
                # keep the WAF's own value type
                cfg['cdn'] = 0 if isinstance(v, (int, float)) and not isinstance(v, bool) else \
                    ('false' if isinstance(v, str) else False)
                changed.append(name)
        if not changed:
            return _ret(True, 'No btwaf site uses CDN header mode, nothing to change')
        if not os.path.isdir(BACKUP_PATH):
            os.makedirs(BACKUP_PATH)
        backup = os.path.join(BACKUP_PATH, 'site.json.%s' % time.strftime('%Y%m%d%H%M%S'))
        shutil.copy2(path, backup)
        _write(path, json.dumps(data))
        self.__nginx_reload()
        return _ret(True, 'Disabled CDN header mode for: %s (backup: %s)' % (', '.join(changed), backup))

    def get_logs(self, get):
        lines = []
        if os.path.exists(SPOOF_LOG):
            _, out = _run('tail -n 100 %s' % SPOOF_LOG)
            lines += [l for l in out.splitlines() if l.strip()]
        if os.path.exists(ERROR_LOG):
            _, out = _run("tail -n 5000 %s | grep '\\[xff_guard\\]' | tail -n 100" % ERROR_LOG)
            lines += [l for l in out.splitlines() if l.strip()]
        return _ret(True, 'ok', lines[::-1])

    def preview(self, get):
        conf = self.__load()
        info = self.__nginx_info()
        engine = 'lua' if (conf.get('lua_guard') and info['lua']) else 'native'
        return _ret(True, 'ok', self.__render(conf, engine))


if __name__ == '__main__':
    # install.sh calls this on uninstall so every file the plugin touched is restored
    if len(sys.argv) > 1 and sys.argv[1] == 'uninstall':
        print(xff_guard_main().disable(None)['msg'])
