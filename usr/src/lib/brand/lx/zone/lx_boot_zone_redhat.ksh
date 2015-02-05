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
# Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
#

#
# Since CentOS, Red Hat Enterprise Linux, and Fedora all use approximately
# the same source, this file should be good for all three.
#
# Currently, this file assumed a pre-systemd existence, so this should be
# CentOS 6.x or earlier.  Testing has been done on CentOS 6.6.
#

# This script was taken from an earlier file.  Initialize some variables here.
install_aborted="Install aborted"
disable_failed="Disable failed"
create_failed="Create failed"
tag=lx-redhat.$$
tmpfile=/tmp/$tag
cmd2_failed=lx_boot_zone_redhat

# Function for setting up networking in the zone.
# Generate the /etc/rc.d/init,d/network rc script
setup_net()
{
    zonecfg -z $ZONENAME info net >/tmp/$ZONENAME.$$
    zonecfg -z $ZONENAME info attr name=resolvers >>/tmp/$ZONENAME.$$
    rm -f $ZONEROOT/tmp/.lx_net_up

    awk '
        BEGIN {
            printf("#! /bin/bash \n\n")
            printf("# network       Bring up/down networking\n#\n")
	    printf("### BEGIN INIT INFO\n");
	    printf("# Provides: $network\n");
	    printf("# Should-Start: iptables ip6tables\n");
	    printf("# Short-Description: Bring up/down networking\n");
	    printf("# Description: Bring up/down networking\n");
	    printf("### END INIT INFO\n\n");

            printf("case \"\$1\" in\n")
            printf("  start)\n")
            printf("    [ \"\$EUID\" != \"0\" ] && exit 4\n")
            printf("    [ -f /tmp/.lx_net_up ] && exit 0\n")
            printf("    touch /tmp/.lx_net_up\n\n")
            printf("    /sbin/ipmgmtd || true\n")
            printf("    /sbin/ifconfig-native lo0 plumb\n")
            printf("    /sbin/ifconfig-native lo0 up\n")
            printf("    /sbin/ifconfig-native lo0 inet6 plumb\n")
            printf("    /sbin/ifconfig-native lo0 inet6 up\n")

	} {
            if ($1 == "net:") {
                in_net = 1
                in_attr = 0
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

                if ($1 == "net:" && phys != "") {
                    printf("    /sbin/ifconfig-native %s plumb || true\n", phys)
                    printf("    /sbin/ifconfig-native %s %s netmask %s up || true\n",
                        phys, ip, mask)
                    printf("    /sbin/ifconfig-native %s inet6 plumb up || true\n", phys)
                    if (prim == "true" && length(gw) > 0)

                        printf("    /sbin/route add default %s || true\n", gw)

                    phys = ""
                    prim = ""
                    gw = ""
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

            printf("    touch /var/lock/subsys/network\n")
            printf("    rc=0\n")
            printf("    ;;\n")
            printf("  stop)\n")
            printf("    [ \"\$EUID\" != \"0\" ] && exit 4\n\n")
	    printf("    rm -f /var/lock/subsys/network\n")
            printf("    rc=0\n")
	    printf("    ;;\n")
	    printf("  status)\n")
	    printf("    echo \"Configured devices:\"\n")
	    printf("    echo \"lo \$(cd /dev/net; ls)\"\n")
	    printf("    echo \"Currently active devices:\"\n")
	    printf("    echo \$(/sbin/ip -o link show up | awk -F \": \" %s{ print \$2 }%s)\n", "\047", "\047")
            printf("    rc=0\n")
	    printf("    ;;\n")
	    printf("  restart|reload|force-reload)\n")
	    printf("    cd \"\$CWD\"\n")
	    printf("    \$0 stop\n")
	    printf("    \$0 start\n")
	    printf("    rc=\$?\n")
	    printf("    ;;\n")
	    printf("  *)\n")
	    printf("    echo \"Usage: \$0 {start|stop|status|restart|reload|force-reload}\"\n")
	    printf("    exit 2\n")
	    printf("esac\n\n")
	    printf("exit \$rc\n")

        }' /tmp/$ZONENAME.$$ > $fnm
	chmod +x $fnm

	rm -f /tmp/$ZONENAME.$$
}

#
# The default /etc/inittab might spawn mingetty on each of the virtual consoles
# as well as xdm on the X console.  Since we don't have virtual consoles nor
# an X console, spawn a single mingetty on /dev/console instead.
#
# Don't bother changing the file if it looks like we already did.
#
if ! egrep -s "Modified by lx brand" $ZONEROOT/etc/inittab; then
	sed 's/^[1-6]:/# Disabled by lx brand: &/
	    s/^id:5:initdefault:/id:3:initdefault: &/' \
	    $ZONEROOT/etc/inittab > $tmpfile
	echo "# Modified by lx brand" >> $tmpfile

	#
	# Attempt to save off the original inittab
	# before moving over the modified version.
	#
	mv -f $ZONEROOT/etc/inittab $ZONEROOT/etc/inittab.$tag 2>/dev/null
	mv -f $tmpfile $ZONEROOT/etc/inittab
	chmod 644 $ZONEROOT/etc/inittab
fi

#
# We use our own way of bringing up networking, so don't let the init system
# try.
#

mv -f $ZONEROOT/etc/sysconfig/network $ZONEROOT/etc/sysconfig/network.$tag \
    2>/dev/null

cat > $ZONEROOT/etc/sysconfig/network <<- EOF
	NETWORKING="no"
	#
	# To enable networking, change the "no" above to "yes" and
	# uncomment and fill in the following parameters.
	#
	# If you are specifying a hostname by name rather than by IP address,
	# be sure the system can resolve the name properly via the use of a
	# name service and/or the proper name files, as specified by
	# nsswitch.conf.  See nsswitch.conf(5) for further details.
	#
	# HOSTNAME=your_hostname_here
	#
EOF

#
# SELinux must be disabled otherwise we won't get past init.
#
egrep -s "^SELINUX=enforcing|^SELINUX=permissive" $ZONEROOT/etc/selinux/config
if [[ $? -eq 0 ]]; then
	tmpfile=/tmp/selinux_config.$$

	sed 's/^SELINUX=.*$/SELINUX=disabled/' \
	    $ZONEROOT/etc/selinux/config > $tmpfile

	mv -f $ZONEROOT/etc/selinux/config \
	    $ZONEROOT/etc/selinux/config.$tag 2>/dev/null
	mv -f $tmpfile $ZONEROOT/etc/selinux/config
	chmod 644 $ZONEROOT/etc/selinux/config
fi

#
# /etc/rc.d/init.d/keytable tries to load a physical keyboard map, which won't
# work in a zone. If we remove etc/sysconfig/keyboard, it won't try this at all.
#
mv -f $ZONEROOT/etc/sysconfig/keyboard $ZONEROOT/etc/sysconfig/keyboard.$tag \
    2>/dev/null

#
# The following scripts attempt to start services or otherwise configure
# the system in ways incompatible with zones, so don't execute them at boot
# time.
#
unsupported_rc_services="
	auditd
	gpm
	hpoj
	ip6tables
	iptables
	irda
	irqbalance
	iscsi
	isdn
	kudzu
	mdmpd
	mdmonitor
	microcode_ctl
	netdump
	pcmcia
	psacct
	random
	rawdevices
	smartd
"

for file in $unsupported_rc_services; do
	if [[ -a "$ZONEROOT/etc/rc.d/init.d/$file" ]]; then
		mv -f "$ZONEROOT/etc/rc.d/init.d/$file" \
		    "$ZONEROOT/etc/rc.d/init.d/$file.$tag"
	fi

	rc_files="$(echo $ZONEROOT/etc/rc.d/rc[0-6].d/[SK]+([0-9])$file)"

	if [[ "$rc_files" != \
	    "$ZONEROOT/etc/rc.d/rc[0-6].d/[SK]+([0-9])$file" ]]; then
		for file in $rc_files; do
			rm -f "$file"
		done
	fi
done

disable_svc()
{
	# XXX - TBD does this work like on Ubuntu?
	#
	# fnm=$ZONEROOT/etc/init/$1.override
	# [[ -h $fnm || -f $fnm ]] && return
	# echo "manual" > $fnm

	fnm=$ZONEROOT/etc/init/$1.conf
	rm -f $fnm
}

RMSVCS="ttyS0"

#
# Now customize upstart
#

for f in $RMSVCS
do
	disable_svc $f
done

if [[ ! -f $ZONEROOT/etc/init/tty.override ]]; then
	cat > $ZONEROOT/etc/init/tty.override <<- EOF
	# tty - getty
	#
	# This service maintains a getty on the console.

	stop on runlevel [S016]

	respawn
	instance console
	exec /sbin/mingetty console
EOF
fi

if [[ ! -f $ZONEROOT/etc/init/start-ttys.override ]]; then
	cat > $ZONEROOT/etc/init/start-ttys.override <<- EOF
	# This service starts the configured number of gettys.
	#

	start on stopped rc RUNLEVEL=[2345]

	task
	script
		initctl start tty
	end script
EOF
fi

#
# There is a lot of stuff in the standard halt and reboot scripts that we
# have no business running in a zone.  Fortunately, the stuff we want to
# skip is all in one contiguous chunk.
#
# Don't bother to modify the file if it looks like we already did.
#
if ! egrep -s "Disabled by lx brand" $ZONEROOT/etc/rc.d/init.d/halt; then
	awk 'BEGIN {skip = ""}
	    /^# Save mixer/ {skip = "# Disabled by lx brand: "}
	    /halt.local/ {skip = ""}
	    /./ {print skip $0}' $ZONEROOT/etc/rc.d/init.d/halt > /tmp/halt.$$

	if [[ $? -eq 0 ]]; then
		mv -f $ZONEROOT/etc/rc.d/init.d/halt \
		    $ZONEROOT/etc/rc.d/init.d/halt.$tag 2>/dev/null
		mv -f /tmp/halt.$$ $ZONEROOT/etc/rc.d/init.d/halt
		chmod 755 $ZONEROOT/etc/rc.d/init.d/halt
	fi
fi

#
# Fix up /etc/rc.d/rc.sysinit:
#
# 1) /sbin/hwclock requires the iopl() system call, which BrandZ won't support.
#    Since the hardware clock cannot be set from within a zone, we comment out
#    the line.
#
# 2) Disable dmesg commands, since we don't implement klogctl
#
# 3) Disable initlog and the mount of /dev/pts
#
# 4) Don't touch /dev/tty* in order to start virtual terminals, as that won't
#    work from within a zone.
#
# 5) Don't try to check the root filesystem (/) as there is no associated
#    physical device, and any attempt to run fsck will fail.
#
# Don't modify the rc.sysinit file if it looks like we already did.
#
if ! egrep -s "Disabled by lx brand" $ZONEROOT/etc/rc.d/rc.sysinit; then
	tmpfile=/tmp/lx_rc.sysinit.$$

	sed 's@^/sbin/hwclock@# Disabled by lx brand: &@
	    s@^HOSTTYPE=@HOSTTYPE=\"s390\" # Spoofed for lx brand: &@
	    s@/bin/dmesg -n@: # Disabled by lx brand: &@
	    s@^dmesg -s@# Disabled by lx brand: &@
	    s@initlog -c \"fsck@: # Disabled by lx brand: &@
	    s@^.*mount .* /dev/pts$@# Disabled by lx brand: &@' \
	    $ZONEROOT/etc/rc.d/rc.sysinit > $tmpfile

	#
	# Attempt to save off the original rc.sysinit
	# before moving over the modified version.
	#
	mv -f $ZONEROOT/etc/rc.d/rc.sysinit \
	    $ZONEROOT/etc/rc.d/rc.sysinit.$tag 2>/dev/null
	mv -f $tmpfile $ZONEROOT/etc/rc.d/rc.sysinit
	chmod 755 $ZONEROOT/etc/rc.d/rc.sysinit
fi


# NOTE: The networking setup assumes an exclusive-stack zone.
iptype=`/usr/sbin/zonecfg -z $ZONENAME info ip-type | cut -f2 -d' '`

if [[ "$iptype" == "exclusive" ]]; then
	fnm=$ZONEROOT/etc/rc.d/init.d/network
	if [[ ! -h $fnm && -f $fnm ]] then
		setup_net
	fi
fi

#
# upstart modifications are complete
#

# Hand control back to lx_boot
