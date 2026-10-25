#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

install_path=/www/server/panel/plugin/xff_guard
guard_conf=/www/server/panel/vhost/nginx/0.xff_guard.conf
snippet=/www/server/nginx/conf/xff_guard_server.conf

Install_xff_guard()
{
    mkdir -p $install_path/backup
    echo 'Installing XFF Guard...'
    echo '================================================'
    echo 'Done. Open the plugin and click "Save & apply".'
    echo '================================================'
}

Uninstall_xff_guard()
{
    # let the plugin undo everything it changed (site includes, fastcgi.conf,
    # reverse-proxy configs, taken-over real-IP files)
    py=/www/server/panel/pyenv/bin/python3
    [ -x $py ] || py=$(command -v python3 || command -v python)
    if [ -n "$py" ] && [ -f $install_path/xff_guard_main.py ]; then
        $py $install_path/xff_guard_main.py uninstall
    fi

    # fallback cleanup in case the step above could not run
    sed -i '/#XFF_GUARD/d' /www/server/panel/vhost/nginx/*.conf /www/server/nginx/conf/fastcgi.conf /www/server/nginx/conf/fastcgi_params 2>/dev/null
    for f in /www/server/panel/vhost/nginx/*.conf.xff_guard_off; do
        [ -f "$f" ] && mv "$f" "${f%.xff_guard_off}"
    done
    rm -f $guard_conf $snippet
    if /www/server/nginx/sbin/nginx -t -c /www/server/nginx/conf/nginx.conf >/dev/null 2>&1; then
        /etc/init.d/nginx reload >/dev/null 2>&1 || /www/server/nginx/sbin/nginx -s reload
    fi
    rm -rf $install_path
    echo 'XFF Guard uninstalled'
}

action=$1
if [ "${1}" == 'install' ]; then
    Install_xff_guard
else
    Uninstall_xff_guard
fi
