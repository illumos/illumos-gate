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
# Copyright 2015 Joyent, Inc.
# Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
#

#
# Since CentOS, Red Hat Enterprise Linux, and Fedora all use approximately
# the same source, this file should be good for all three.
#
# Currently, this file assumed a pre-systemd existence, so this should be
# CentOS 6.x or earlier.  Testing has been done on CentOS 6.6.
#

tmpfile=/tmp/lx-redhat.$$


# Before doing anything else, make sure some Centos-specific dirs are safe.
# /etc/init.d is normally a symlink so we can't easily tell if it's safe so
# check rc.d/init.d instead.

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

# Generate the /etc/rc.d/init.d/network rc script
cat > $tmpfile <<EOF
#!/bin/bash
# network       Bring up/down networking
#
### BEGIN INIT INFO
# Provides: \$network
# Short-Description: Bring up/down networking
# Description: Bring up/down networking
### END INIT INFO

case "\$1" in
    start)
    [ "\$EUID" != "0" ] && exit 4

    if [ ! -e /etc/resolv.conf ]; then
        if [ -h /etc/resolv.conf ]; then
            rm -f /etc/resolv.conf
        fi
        echo "# AUTOMATIC ZONE CONFIG" > /etc/resolv.conf
$(zonecfg -z $ZONENAME info attr name=resolvers |
awk '
    {
        if ($1 == "value:") {
            nres = split($2, resolvers, ",")
        }
    }
    END {
        for (i = 1; i <= nres; i++) {
            printf("        echo \"nameserver %s\" >> %s\n", resolvers[i],
                "/etc/resolv.conf")
        }
    }
')
    fi
    touch /var/lock/subsys/network
    rc=0
    ;;
  stop)
    [ "\$EUID" != "0" ] && exit 4

    rm -f /var/lock/subsys/network
    rc=0
    ;;
  status)
    echo "Configured devices:"
    echo "lo \$(cd /dev/net; ls)"
    echo "Currently active devices:"
    echo \$(/sbin/ip -o link show up | awk -F ": " '{ print \$2 }')
    rc=0
    ;;
  restart|reload|force-reload)
    cd "\$CWD"
    \$0 stop
    \$0 start
    rc=\$?
    ;;
  *)
    echo "Usage: \$0 {start|stop|status|restart|reload|force-reload}"
    exit 2
esac

exit \$rc
EOF
fnm=$ZONEROOT/etc/rc.d/init.d/network
if [[ -f $fnm || -h $fnm ]]; then
	mv -f $tmpfile $fnm
	chmod 755 $fnm
fi

# This is specific to a systemd-based image
sysdir=$ZONEROOT/etc/systemd/system
if [[ -d $ZONEROOT/etc && ! -h $ZONEROOT/etc && -d $ZONEROOT/etc/systemd &&
    ! -h $ZONEROOT/etc/systemd && -d $sysdir && ! -h $sysdir ]]; then
    # don't use NetworkManager
    rm -f $sysdir/dbus-org.freedesktop.nm-dispatcher.service
    rm -f $sysdir/multi-user.target.wants/NetworkManager.service
    rm -f $sysdir/dbus-org.freedesktop.NetworkManager.service
    # our network setup needs to run
    fnm=$sysdir/multi-user.target.wants/network.service
    if [[ ! -f $fnm ]]; then
        ln -s /etc/rc.d/init.d/network \
            $sysdir/multi-user.target.wants/network.service
    fi
fi

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
fnm=$ZONEROOT/etc/rc.d/rc.sysinit
tmpfile=/tmp/lx_rc.sysinit.$$

sed 's@^/sbin/hwclock@# lx: &@
    s@^/bin/dmesg -n@# lx: &@
    s@^dmesg -s@# lx: &@
    s@^initlog -c \"fsck@# lx: &@
    s@^mount -n -o remount /dev/shm @mount -t tmpfs tmpfs /dev/shm @
    s@^mount .* /dev/pts@# lx: &@
    /^#remount \/dev\/shm/d' \
    $fnm > $tmpfile

if [[ ! -h $fnm ]]; then
	mv -f $tmpfile $fnm
	chmod 755 $fnm
fi

#
# sysinit modifications are complete
#
rm -f $tmpfile

# Hand control back to lx_boot
