#!/bin/ksh -p
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2014 Joyent, Inc.  All rights reserved.
#

#
# Customisation for Ubuntu-based distributions.  Assumes to have been
# sourced from lx_boot.
#

# Generate the networking.conf upstart script 
setup_net()
{
    [ -f /etc/defaultrouter ] && defroute=`cat /etc/defaultrouter`

    zonecfg -z $ZONENAME info net | awk -v defroute=$defroute '
        BEGIN {
            printf("description\t\"configure virtual network devices\"\n\n")
            printf("emits static-network-up\n")
	    printf("emits net-device-up\n\n")

	    printf("start on local-filesystems\n\n")

	    printf("task\n\n")

	    printf("pre-start exec mkdir -p /run/network\n\n")

	    printf("script\n")
	    printf("    /sbin/ipmgmtd || true\n")
	    printf("    /sbin/ifconfig-native lo0 plumb\n")
	    printf("    /sbin/ifconfig-native lo0 up\n")
	    printf("    /sbin/initctl emit --no-wait net-device-up IFACE=lo LOGICAL=lo ADDRFAM=inet METHOD=loopback || true\n")

        } {
            if ($1 == "physical:") {
                phys = $2
            } else if ($1 == "property:") {
                split($2, a, ",")
                split(a[1], k, "=")
                split(a[2], v, "=")

                val = substr(v[2], 2)
                val = substr(val, 1, length(val) - 2)

                if (k[2] == "ip")
                    ip = val
                else if (k[2] == "netmask")
                    mask = val
                else if (k[2] == "primary")
                    prim = val
            }

            if ($1 == "net:" && phys != "") {
		printf("    /sbin/ifconfig-native %s plumb || true\n", phys)
		printf("    /sbin/ifconfig-native %s %s netmask %s up || true\n",
		    phys, ip, mask)
		printf("    /sbin/initctl emit --no-wait net-device-up IFACE=%s\n",
		     phys)

                phys = ""
                prim = ""
            }
        }
        END {
	    printf("    /sbin/ifconfig-native %s plumb || true\n", phys)
	    printf("    /sbin/ifconfig-native %s %s netmask %s up || true\n",
		phys, ip, mask)
	    printf("    /sbin/initctl emit --no-wait net-device-up IFACE=%s\n",
		phys)

	    printf("    /sbin/initctl emit --no-wait static-network-up\n")
	    if (length(defroute) > 0)
	        printf("    /sbin/route add default %s\n", defroute)
	    printf("end script\n")
        }' > $fnm
}

RMSVCS="acpid.conf
	control-alt-delete.conf
	console-setup.conf
	dmesg.conf
	hwclock.conf
	hwclock-save.conf
	irqbalance.conf
	module-init-tools.conf
	mounted-dev.conf
	mounted-debugfs.conf
	network-interface-security.conf
	plymouth.conf
	plymouth-log.conf
	plymouth-splash.conf
	plymouth-stop.conf
	plymouth-upstart-bridge.conf
	setvtrgb.conf
	tty1.conf
	tty2.conf
	tty3.conf
	tty4.conf
	tty5.conf
	tty6.conf
	upstart-udev-bridge.conf
	udev.conf
	udevmonitor.conf
	udevtrigger.conf
	udev-fallback-graphics.conf
	udev-finish.conf
	ureadahead-other.conf
	ureadahead.conf
	whoopsie.conf"


#
# Now customize upstart
#

for f in $RMSVCS
do
	fnm=$ZONEROOT/etc/init/$f
	[[ ! -h $fnm && -f $fnm ]] && rm -f $fnm
done

fnm=$ZONEROOT/etc/init/console.conf
if [[ ! -h $fnm && -f $fnm ]] then
	sed -e 's/lxc/zones/' $fnm > /tmp/console.conf.$$
	mv /tmp/console.conf.$$ $fnm
fi

fnm=$ZONEROOT/etc/init/container-detect.conf
if [[ ! -h $fnm && -f $fnm ]] then
	cat <<'DONE' > $fnm
description "Track if upstart is running in a container"

start on mounted MOUNTPOINT=/run

env container
env LIBVIRT_LXC_UUID

emits container

pre-start script
    container=zones
    echo "$container" > /run/container_type || true
    initctl emit --no-wait container CONTAINER=$container
    exit 0
end script
DONE
fi

# XXX need to add real mounting into this svc definition

fnm=$ZONEROOT/etc/init/mountall.conf
if [[ ! -h $fnm && -f $fnm ]] then
	cat <<'DONE' > $fnm
description	"Mount filesystems on boot"

start on startup

task

emits virtual-filesystems
emits local-filesystems
emits remote-filesystems
emits all-swaps
emits filesystem
emits mounted

script
    echo "/ / zfs rw 0 0" > /etc/mtab
    echo "proc /proc proc rw,noexec,nosuid,nodev 0 0" >> /etc/mtab

    /sbin/initctl emit --no-wait virtual-filesystems
    /bin/mount -t tmpfs tmpfs /run || true
    /sbin/initctl emit --no-wait mounted MOUNTPOINT=/run TYPE=tmpfs
    /sbin/initctl emit --no-wait local-filesystems
    /sbin/initctl emit --no-wait all-swaps
    /sbin/initctl emit --no-wait filesystem
end script
DONE
fi

iptype=`/usr/sbin/zonecfg -z $ZONENAME info ip-type | cut -f2 -d' '`

if [[ "$iptype" == "exclusive" ]]; then
	fnm=$ZONEROOT/etc/init/networking.conf
	if [[ ! -h $fnm && -f $fnm ]] then
		setup_net
	fi
fi

fnm=$ZONEROOT/etc/init/plymouth-ready.conf
if [[ ! -h $fnm && -f $fnm ]] then
	cat <<'DONE' > $fnm
description "Send an event to indicate plymouth is up"

task
start on startup
instance $UPSTART_EVENTS

emits plymouth-ready

script
  initctl emit --no-wait plymouth-ready
end script
DONE
fi

#
# upstart modifications are complete 
#

# Hand control back to lx_boot
