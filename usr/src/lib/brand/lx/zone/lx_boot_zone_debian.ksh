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
# Copyright 2015 Joyent, Inc.  All rights reserved.
#

#
# Customisation for Debian-based distributions.  Assumes to have been
# sourced from lx_boot.
#

tmpfile=/tmp/lx-debian.$$

# Generate the networking.conf upstart script 
setup_net()
{
    zonecfg -z $ZONENAME info net >/tmp/$ZONENAME.$$
    zonecfg -z $ZONENAME info attr name=resolvers >>/tmp/$ZONENAME.$$

    awk '
        BEGIN {
            printf("#!/bin/sh -e\n")
	    printf("### BEGIN INIT INFO\n");
	    printf("# Provides: networking ifupdown\n");
	    printf("# Required-Start: mountkernfs $local_fs urandom\n");
	    printf("# Required-Stop: $local_fs\n");
	    printf("# Default-Start: S\n");
	    printf("# Default-Stop: 0 6\n");
	    printf("# Short-Description: Raise network interfaces.\n");
	    printf("# Description: Bring up/down networking\n");
	    printf("### END INIT INFO\n\n");

	    printf(". /lib/lsb/init-functions\n\n");

            printf("case \"\$1\" in\n")
            printf("  start)\n")
	    printf("    log_action_begin_msg \"Configuring network interfaces\"\n")
            printf("    /sbin/ipmgmtd || true\n")
            printf("    /sbin/ifconfig-native lo0 plumb\n")
            printf("    /sbin/ifconfig-native lo0 up\n")
            printf("    /sbin/ifconfig-native lo0 inet6 plumb\n")
            printf("    /sbin/ifconfig-native lo0 inet6 up\n")

	} {
            if ($1 == "net:") {
                in_net = 1
                in_attr = 0

                if (phys != "") {
                    printf("    /sbin/ifconfig-native %s plumb || true\n", phys)
                    printf("    /sbin/ifconfig-native %s %s netmask %s up || true\n",
                        phys, ip, mask)
                    printf("    /sbin/ifconfig-native %s inet6 plumb up || true\n", phys)
                    if (prim == "true" && length(gw) > 0)

                        printf("    /sbin/route add default %s || true\n", gw)

                    phys = ""
                    prim = ""
                    gw = ""
                    ip = ""
                    mask = ""
                }
                next

            } else if ($1 == "attr:") {
                in_net = 0
                in_attr = 1
                next
            }

            if (in_net == 1) {
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
                    else if (k[2] == "gateway")
                        gw = val
                }

            } else if (in_attr == 1) {
                if ($1 == "value:") {
                    nres = split($2, resolvers, ",")
                }
            }
        }
        END {
            printf("    /sbin/ifconfig-native %s plumb || true\n", phys)
            printf("    /sbin/ifconfig-native %s %s netmask %s up || true\n",
                phys, ip, mask)
            printf("    /sbin/ifconfig-native %s inet6 plumb up || true\n", phys)
            if (prim == "true" && length(gw) > 0)
                printf("    /sbin/route add default %s || true\n", gw)

            printf("    rm -f /etc/resolv.conf\n")
            for (i = 1; i <= nres; i++)
                printf("    echo \"nameserver %s\" >> %s\n", resolvers[i],
                    "/etc/resolv.conf")

	    printf("    log_action_end_msg 0\n")
            printf("    rc=0\n")
            printf("    ;;\n")
            printf("  stop)\n")
            printf("    rc=0\n")
	    printf("    ;;\n")
	    printf("  restart|reload|force-reload)\n")
	    printf("    cd \"\$CWD\"\n")
	    printf("    \$0 stop\n")
	    printf("    \$0 start\n")
	    printf("    rc=\$?\n")
	    printf("    ;;\n")
	    printf("  *)\n")
	    printf("    echo \"Usage: \$0 {start|stop|restart|reload|force-reload}\"\n")
	    printf("    exit 1\n")
	    printf("esac\n\n")
	    printf("exit \$rc\n")

        }' /tmp/$ZONENAME.$$ > $fnm
	chmod +x $fnm

	rm -f /tmp/$ZONENAME.$$
}

#
# Before doing anything else, make sure some Centos-specific dirs are safe.
# /etc/init.d is normally a symlink so we can't easily tell if it's safe so
# check rc.d/init.d instead.
#
safe_dir /etc/init.d
safe_dir /etc/rc0.d
safe_dir /etc/rc1.d
safe_dir /etc/rc2.d
safe_dir /etc/rc3.d
safe_dir /etc/rc4.d
safe_dir /etc/rc5.d
safe_dir /etc/rc6.d
safe_dir /etc/rcS.d
safe_opt_dir /etc/selinux

#
# The default /etc/inittab might spawn mingetty on each of the virtual consoles
# as well as xdm on the X console.  Since we don't have virtual consoles nor
# an X console, spawn a single mingetty on /dev/console instead.
#
# Don't bother changing the file if it looks like we already did.
#
fnm=$ZONEROOT/etc/inittab
if ! egrep -s "Modified by lx brand" $fnm; then
	sed 's/^[1-6]:/# Disabled by lx brand: &/' \
	    $fnm > $tmpfile
	echo "1:2345:respawn:/sbin/getty 38400 console" >> $tmpfile
	echo "# Modified by lx brand" >> $tmpfile

	if [[ ! -h $fnm ]]; then
		mv -f $tmpfile $fnm
		chmod 644 $fnm
	fi
fi

# The Debian init uses a combination of traditional rc-style service
# definitions and upstart-style definitions.

#
# The following rc-style scripts attempt to start services or otherwise
# configure the system in ways incompatible with zones, so don't execute them
# at boot time.
#
unsupported_rc_services="
	checkfs.sh
	checkroot.sh
	hwclock.sh
	kmod
	mtab.sh
	procps
	udev
	udev-mtab
"

for file in $unsupported_rc_services; do
	rm -f $ZONEROOT/etc/init.d/$file

	rc_files="$(echo $ZONEROOT/etc/rc[0-6S].d/[SK]+([0-9])$file)"

	if [[ "$rc_files" != \
	    "$ZONEROOT/etc/rc[0-6S].d/[SK]+([0-9])$file" ]]; then
		for file in $rc_files; do
			rm -f "$file"
		done
	fi
done

disable_svc()
{
	fnm=$ZONEROOT/etc/init/$1.override
	[[ -h $fnm || -f $fnm ]] && return
	echo "manual" > $fnm
}


#
# Now customize upstart
#

RMSVCS="
	network-interface-security
	udev
	udevmonitor
	udevtrigger
	udev-fallback-graphics
	udev-finish
"
for f in $RMSVCS
do
	disable_svc $f
done

iptype=`/usr/sbin/zonecfg -z $ZONENAME info ip-type | cut -f2 -d' '`

if [[ "$iptype" == "exclusive" ]]; then
	fnm=$ZONEROOT/etc/init.d/networking
	if [[ ! -h $fnm && -f $fnm ]] then
		setup_net
	fi
fi

#
# We need to setup for the /dev/shm mount. Unlike some other distros, Debian
# can handle it as either /dev/shm or /run/shm. For simplicity we create an
# fstab entry to force it into the /dev/shm style.
#
fnm=$ZONEROOT/etc/fstab
entry=$(awk '{if ($2 == "/dev/shm") print $2}' $fnm)
if [[ -z "$entry" && ! -h $fnm ]]; then
    echo "swapfs    /dev/shm    tmpfs    defaults    0 0" >> $fnm
fi

#
# upstart modifications are complete 
#

# Hand control back to lx_boot
