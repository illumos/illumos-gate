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
# Copyright 2016 Joyent, Inc.
#

#
# Customisation for Ubuntu-based distributions.  Assumes to have been
# sourced from lx_boot.
#
tmpfile=/tmp/lx-ubuntu.$$

# Check that the directories we're writing to aren't symlinks outside the zone
safe_dir /etc
safe_dir /etc/init
safe_dir /etc/resolvconf
safe_dir /etc/resolvconf/resolv.conf.d
safe_dir /etc/network
safe_dir /etc/network/interfaces.d
safe_dir /etc/network/interfaces.d/smartos

# Populate resolve.conf setup files
zonecfg -z $ZONENAME info attr name=resolvers | awk '
BEGIN {
	print("# AUTOMATIC ZONE CONFIG")
}
$1 == "value:" {
	nres = split($2, resolvers, ",");
	for (i = 1; i <= nres; i++) {
		print("nameserver", resolvers[i]);
	}
}
' > $tmpfile
zonecfg -z $ZONENAME info attr name=dns-domain | awk '
$1 == "value:" {
	dom = $2
}
END {
	print("search", dom);
}
' >> $tmpfile
fnm=$ZONEROOT/etc/resolvconf/resolv.conf.d/tail
if [[ -f $fnm || -h $fnm || ! -e $fnm ]]; then
	mv -f $tmpfile $fnm
fi

# Override network configuration
zonecfg -z $ZONENAME info net | awk '
BEGIN {
	print("# AUTOMATIC ZONE CONFIG")
}
$1 == "physical:" {
	print("iface", $2, "inet manual");
}
' > $tmpfile
fnm=$ZONEROOT/etc/network/interfaces.d/smartos
if [[ -f $fnm || -h $fnm ]]; then
	mv -f $tmpfile $fnm
fi

src_fnm=$ZONEROOT/etc/init/console.conf
tgt_fnm=$ZONEROOT/etc/init/console.override
if [[ -f $src_fnm && ! -f $tgt_fnm && ! -h $tgt_fnm ]] then
	sed -e 's/lxc/smartos/' $src_fnm > /tmp/console.conf.$$
	mv /tmp/console.conf.$$ $tgt_fnm
fi

fnm=$ZONEROOT/etc/init/container-detect.override
if [[ ! -f $fnm && ! -h $fnm ]] then
	cat <<'DONE' > $fnm
description "Track if upstart is running in a container"

start on mounted MOUNTPOINT=/run

env container
env LIBVIRT_LXC_UUID

emits container

pre-start script
    container=smartos
    echo "$container" > /run/container_type || true
    initctl emit --no-wait container CONTAINER=$container
    exit 0
end script
DONE
fi

# XXX need to add real mounting into this svc definition

fnm=$ZONEROOT/etc/init/mountall.override
if [[ ! -h $fnm ]] then
	cat <<DONE > $fnm
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
    echo "/dev/zfsds0 / zfs rw 0 0" > /etc/mtab
    echo "proc /proc proc rw,noexec,nosuid,nodev 0 0" >> /etc/mtab

    /sbin/initctl emit --no-wait virtual-filesystems
    /bin/mount -t tmpfs tmpfs /dev/shm || true
    /bin/mount -t tmpfs tmpfs /run || true
    /bin/mkdir -p /run/lock || true
    /bin/ln -s /dev/shm /run/shm || true
    /sbin/initctl emit --no-wait mounted MOUNTPOINT=/run TYPE=tmpfs
    /sbin/initctl emit --no-wait local-filesystems
    /sbin/initctl emit --no-wait all-swaps
    /sbin/initctl emit --no-wait filesystem
end script
DONE
fi

#
# upstart modifications are complete
#
rm -f $tmpfile

# Hand control back to lx_boot
