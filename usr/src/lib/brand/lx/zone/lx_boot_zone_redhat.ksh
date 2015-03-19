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
tmpfile=/tmp/lx-redhat.$$

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
# Before doing anything else, make sure some Centos-specific dirs are safe.
# /etc/init.d is normally a symlink so we can't easily tell if it's safe so
# check rc.d/init.d instead.
#
safe_dir /etc/sysconfig
safe_dir /etc/rc.d
safe_dir /etc/rc.d/init.d
safe_dir /etc/rc.d/rc0.d
safe_dir /etc/rc.d/rc1.d
safe_dir /etc/rc.d/rc2.d
safe_dir /etc/rc.d/rc3.d
safe_dir /etc/rc.d/rc4.d
safe_dir /etc/rc.d/rc5.d
safe_dir /etc/rc.d/rc6.d
safe_opt_dir /etc/selinux

#
# The default /etc/inittab only sets the runlevel. Make sure it's runlevel 3
# and not runlevel 5 (X11).
# Don't bother changing the file if it looks like we already did.
#
fnm=$ZONEROOT/etc/inittab
if ! egrep -s "Modified by lx brand" $fnm; then
	sed 's/^id:5:initdefault:/id:3:initdefault: &/' \
	    $fnm > $tmpfile
	echo "# Modified by lx brand" >> $tmpfile

	if [[ ! -h $fnm ]]; then
		mv -f $tmpfile $fnm
		chmod 644 $fnm
	fi
fi

#
# Ensure svcs depending on $network will start.
#
fnm=$ZONEROOT/etc/sysconfig/network
if ! egrep -s "NETWORKING=yes" $fnm; then
	cfghnm=$(zonecfg -z $ZONENAME info attr name=hostname | \
	    awk '{if ($1 == "value:") print $2}')
	if [[ -z "$cfghnm" ]]; then
		cfghnm=$ZONENAME
	fi
	if [[ ! -h $fnm ]]; then
		cat > $fnm <<- EOF
		NETWORKING=yes
		HOSTNAME=$cfghnm
		EOF
	fi
fi

#
# SELinux must be disabled otherwise we won't get past init.
#
fnm=$ZONEROOT/etc/selinux/config
if egrep -s "^SELINUX=enforcing|^SELINUX=permissive" $fnm; then
	tmpfile=/tmp/selinux_config.$$

	sed 's/^SELINUX=.*$/SELINUX=disabled/' $fnm > $tmpfile
	if [[ ! -h $fnm ]]; then
		mv -f $tmpfile $fnm
		chmod 644 $fnm
	fi
fi

#
# /etc/rc.d/init.d/keytable tries to load a physical keyboard map, which won't
# work in a zone. If we remove etc/sysconfig/keyboard, it won't try this at all.
#
fnm=$ZONEROOT/etc/sysconfig/keyboard
if [[ ! -h $fnm ]]; then
	rm -f $ZONEROOT/etc/sysconfig/keyboard
fi

# The Centos init uses a combination of traditional rc-style service
# definitions and upstart-style definitions.

#
# The following rc-style scripts attempt to start services or otherwise
# configure the system in ways incompatible with zones, so don't execute them
# at boot time.
#
unsupported_rc_services="
	acpid
	auditd
	gpm
	hpoj
	ip6tables
	iptables
	irda
	irqbalance
	iscsi
	isdn
	kdump
	kudzu
	mdmpd
	mdmonitor
	microcode_ctl
	netdump
	ntpd
	ntpdate
	pcmcia
	psacct
	quota_nld
	random
	rawdevices
	smartd
"

for file in $unsupported_rc_services; do
	rm -f $ZONEROOT/etc/rc.d/init.d/$file

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
	fnm=$ZONEROOT/etc/init/$1.override
	[[ -h $fnm || -f $fnm ]] && return
	echo "manual" > $fnm

	# fnm=$ZONEROOT/etc/init/$1.conf
	# rm -f $fnm
}

RMSVCS="control-alt-delete
	ttyS0"

#
# Now customize upstart services
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
fnm=$ZONEROOT/etc/rc.d/init.d/halt
if ! egrep -s "Disabled by lx brand" $fnm; then
	awk 'BEGIN {skip = ""}
	    /^# Save mixer/ {skip = "# Disabled by lx brand: "}
	    /halt.local/ {skip = ""}
	    /./ {print skip $0}' $fnm > /tmp/halt.$$

	if [[ $? -eq 0 && ! -h $fnm ]]; then
		mv -f /tmp/halt.$$ $fnm
		chmod 755 $fnm
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
fnm=$ZONEROOT/etc/rc.d/rc.sysinit
if ! egrep -s "Disabled by lx brand" $fnm; then
	tmpfile=/tmp/lx_rc.sysinit.$$

	sed 's@^/sbin/hwclock@# Disabled by lx brand: &@
	    s@^HOSTTYPE=@HOSTTYPE=\"s390\" # Spoofed for lx brand: &@
	    s@/bin/dmesg -n@: # Disabled by lx brand: &@
	    s@^dmesg -s@# Disabled by lx brand: &@
	    s@initlog -c \"fsck@: # Disabled by lx brand: &@
	    s@^.*mount .* /dev/pts$@# Disabled by lx brand: &@' \
	    $fnm > $tmpfile

	if [[ ! -h $fnm ]]; then
		mv -f $tmpfile $fnm
		chmod 755 $fnm
	fi
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
