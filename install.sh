#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

install_path=/www/server/panel/plugin/xff_guard
guard_conf=/www/server/panel/vhost/nginx/0.xff_guard.conf

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
    # put back any real-IP file the plugin took over
    for f in /www/server/panel/vhost/nginx/*.conf.xff_guard_off; do
        [ -f "$f" ] && mv "$f" "${f%.xff_guard_off}"
    done
    if [ -f $guard_conf ]; then
        rm -f $guard_conf
        if /www/server/nginx/sbin/nginx -t -c /www/server/nginx/conf/nginx.conf >/dev/null 2>&1; then
            /etc/init.d/nginx reload >/dev/null 2>&1 || /www/server/nginx/sbin/nginx -s reload
        fi
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
