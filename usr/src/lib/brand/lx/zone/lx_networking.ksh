#!/bin/sh -e
### BEGIN INIT INFO
# Provides:          networking
# Required-Start:
# Required-Stop:     $local_fs
# Should-Start:      ifupdown
# Should-Stop:       ifupdown
# Default-Start:
# Default-Stop:      0 6
# Short-Description: Raise network interfaces.
### END INIT INFO

PATH="/sbin:/bin:/usr/sbin:/usr/bin"

[ -x /sbin/ipmgmtd ] || exit 0
[ -x /sbin/ifconfig ] || exit 0

. /lib/lsb/init-functions

[ -f /etc/default/networking ] && . /etc/default/networking

config_ifs() {
    if [ ! -f /etc/network/interfaces ]; then
        return
    fi

    while read cmd nm typ how; do
        if [ "$cmd" = "iface" ]; then
            ifconfig $nm plumb
            if [ "$nm" != "lo0" ]; then
                if [ "$how" = "dhcp" ]; then
                    ifconfig $nm dhcp
                elif [ "$how" = "static" ]; then
                    read nxt addr remain
                    read nxt mask remain
                    ifconfig $nm inet $addr netmask $mask up
                fi
            fi
        fi
    done < /etc/network/interfaces
}

case "$1" in
start)
	/sbin/ipmgmtd

	log_action_begin_msg "Configuring network interfaces"
	config_ifs
	log_action_end_msg $?
	;;

stop)
        log_action_begin_msg "Deconfiguring network interfaces"
        log_action_end_msg $?
        ;;

reload)
        log_action_begin_msg "Reloading network interfaces configuration"
        log_action_end_msg $?
        ;;

force-reload|restart)
        log_warning_msg "Running $0 $1 is deprecated because it may not re-enable some interfaces"
        log_action_begin_msg "Reconfiguring network interfaces"
        log_action_end_msg $?
        ;;

*)
        echo "Usage: /etc/init.d/networking {start|stop|reload|restart|force-reload}"
        exit 1
        ;;
esac

exit 0
