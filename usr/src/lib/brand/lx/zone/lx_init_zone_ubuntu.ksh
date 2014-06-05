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
# sourced from lx_init_zone.
#

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


# Use the debian script to begin with
. $(dirname $0)/lx_init_zone_debian

#
# Now customize upstart
#

for f in $RMSVCS
do
	rm -f etc/init/$f
done

sed -e 's/lxc/zones/' /zones/$zonename/root/etc/init/console.conf \
    >/zones/$zonename/root/etc/init/console.conf.new
mv /zones/$zonename/root/etc/init/console.conf.new \
    /zones/$zonename/root/etc/init/console.conf

cat <<'DONE' > etc/init/container-detect.conf
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

# XXX use original dbus.conf once /run is mounted as a tmpfs mount and we
# don't need to cleanup the pid

cat <<'DONE' > etc/init/dbus.conf
description	"D-Bus system message bus"

start on local-filesystems
stop on deconfiguring-networking

expect fork
respawn

pre-start script
    rm -f /run/dbus/pid

    mkdir -p /var/run/dbus
    chown messagebus:messagebus /var/run/dbus

    exec dbus-uuidgen --ensure
end script

exec dbus-daemon --system --fork --activation=upstart

post-start exec kill -USR1 1

post-stop exec rm -f /var/run/dbus/pid
DONE

# XXX need to add real mounting into this svc definition

cat <<'DONE' > etc/init/mountall.conf
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
    /sbin/initctl emit --no-wait virtual-filesystems
#   mount -F tmpfs swap /run || true
    /sbin/initctl emit --no-wait mounted MOUNTPOINT=/run
    /sbin/initctl emit --no-wait local-filesystems
    /sbin/initctl emit --no-wait all-swaps
    /sbin/initctl emit --no-wait filesystem
end script
DONE

# XXX fix up IP handling and multiple net definitions

iptype=`/usr/sbin/zonecfg -z $zonename info ip-type | cut -f2 -d' '`

if [[ "$iptype" == "exclusive" ]]; then
	ipaddr=`/usr/sbin/zonecfg -z $zonename info net | \
	    nawk -F, '/name=ip/{print substr($2, 8, length($2) - 9)}'`
	netmask=`/usr/sbin/zonecfg -z $zonename info net | \
	    nawk -F, '/name=netmask/{print substr($2,8,length($2)-9)}'`

	cat <<-DONE > etc/init/networking.conf
	description	"configure virtual network devices"

	emits static-network-up
	emits net-device-up

	start on local-filesystems

	task

	pre-start exec mkdir -p /run/network

	script
	    /sbin/ipmgmtd || true
	    /sbin/ifconfig lo0 plumb
	    /sbin/initctl emit --no-wait net-device-up IFACE=lo LOGICAL=lo ADDRFAM=inet METHOD=loopback || true
	    /sbin/ifconfig net0 plumb || true
	    /sbin/ifconfig net0 $ipaddr netmask $netmask up || true
	    /sbin/initctl emit --no-wait net-device-up IFACE=net0
	    /sbin/initctl emit --no-wait static-network-up
	end script
	DONE
fi

cat <<'DONE' > etc/init/plymouth-ready.conf
description "Send an event to indicate plymouth is up"

task
start on startup
instance $UPSTART_EVENTS

emits plymouth-ready

script
  initctl emit --no-wait plymouth-ready
end script
DONE

#
# upstart modifications are complete 
#

# XXX remove this since it blocks login until we can root cause and fix, might
# be the rtnetlink issue

rm -f /zones/$zonename/root/etc/update-motd.d/50-landscape-sysinfo

# Hand control back to lx_init_zone
#
