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
# Customisation for busybox-init-based distributions.  Assumes to have been
# sourced from lx_boot.
#

tmpfile=/tmp/lx-busybox.$$

# Generate the networking.conf upstart script 
setup_net()
{
    zonecfg -z $ZONENAME info net >/tmp/$ZONENAME.$$
    zonecfg -z $ZONENAME info attr name=resolvers >>/tmp/$ZONENAME.$$

    awk '
        BEGIN {
            printf("#!/sbin/runscript\n\n")
	    printf("depend() {\n\tneed localmount\n");
	    printf("\tafter bootmisc hwdrivers modules\n\tprovide net\n");
	    printf("\tkeyword nojail noprefix novserver\n}\n\n");

	    printf("start() {\n")
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
            printf("    /sbin/ifconfig-native %s inet6 plumb up || true\n",
                phys)
            if (prim == "true" && length(gw) > 0)
                printf("    /sbin/route add default %s || true\n", gw)

            printf("    rm -f /etc/resolv.conf\n")
            for (i = 1; i <= nres; i++)
                printf("    echo \"nameserver %s\" >> %s\n", resolvers[i],
                    "/etc/resolv.conf")

	    printf("    return 0\n}\n\n")
            printf("stop() {\n")
            printf("    return 0\n")
	    printf("}\n")
        }' /tmp/$ZONENAME.$$ > $fnm
	chmod +x $fnm

	rm -f /tmp/$ZONENAME.$$
}

#
# Before doing anything else, make sure some dirs are safe.
#
safe_dir /etc/init.d

#
# The default /etc/inittab might spawn mingetty on each of the virtual consoles
# as well as xdm on the X console.  Since we don't have virtual consoles nor
# an X console, spawn a single mingetty on /dev/console instead.
#
# Don't bother changing the file if it looks like we already did.
#
fnm=$ZONEROOT/etc/inittab
if ! egrep -s "Modified by lx brand" $fnm; then
	sed 's/^tty[1-6]:/# Disabled by lx brand: &/' \
	    $fnm > $tmpfile
	echo "console::respawn:/sbin/getty 38400 console" >> $tmpfile
	echo "# Modified by lx brand" >> $tmpfile

	if [[ ! -h $fnm ]]; then
		mv -f $tmpfile $fnm
		chmod 644 $fnm
	fi
fi

#
# The following scripts attempt to start services or otherwise configure the
# system in ways incompatible with zones, so replace them with stubs.
#

fnm=$ZONEROOT/etc/init.d/fsck
[[ ! -h $fnm && -f $fnm ]] && cat <<DONE > $fnm
#!/sbin/runscript

depend() {
    use dev clock modules
}

start() {
    return 0
}
DONE

fnm=$ZONEROOT/etc/init.d/hwclock
[[ ! -h $fnm && -f $fnm ]] && cat <<DONE > $fnm
#!/sbin/runscript

depend() {
    provide clock
}

start() {
    return 0
}
DONE

fnm=$ZONEROOT/etc/init.d/klogd
[[ ! -h $fnm && -f $fnm ]] && cat <<DONE > $fnm
#!/sbin/runscript

depend() {
    need clock hostname localmount
    before net
}

start() {
    return 0
}
DONE

fnm=$ZONEROOT/etc/init.d/sysfs
[[ ! -h $fnm && -f $fnm ]] && cat <<DONE > $fnm
#!/sbin/runscript

depend() {
}

start() {
    return 0
}
DONE

iptype=`/usr/sbin/zonecfg -z $ZONENAME info ip-type | cut -f2 -d' '`
if [[ "$iptype" == "exclusive" ]]; then
	fnm=$ZONEROOT/etc/init.d/networking
	if [[ ! -h $fnm && -f $fnm ]] then
		setup_net
	fi
fi

#
# Setup for the /dev/shm mount.
#
fnm=$ZONEROOT/etc/fstab
entry=$(awk '{if ($2 == "/dev/shm") print $2}' $fnm)
if [[ -z "$entry" && ! -h $fnm ]]; then
    echo "swapfs    /dev/shm    tmpfs    defaults    0 0" >> $fnm
fi

# Hand control back to lx_boot
