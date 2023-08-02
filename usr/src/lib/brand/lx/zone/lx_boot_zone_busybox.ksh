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
# Copyright 2021 Joyent, Inc.
# Copyright 2023 MNX Cloud, Inc.
#

#
# Customisation for busybox-init-based distributions.  Assumes to have been
# sourced from lx_boot.
#

tmpfile=/tmp/lx-busybox.$$

# Check that the directories we're writing to aren't symlinks outside the zone
safe_dir /etc
safe_dir /etc/init.d

# Generate network setup script
#
cat > $tmpfile <<EOF
#!/sbin/runscript
depend() {
    need localmount
    after bootmisc hwdrivers modules
    provide net
    keyword nojail noprefix novserver
}
start() {
EOF
# Only alter resolv.conf if we're getting info from zonecfg(1M).
zonecfg -z $ZONENAME info attr name=resolvers | grep -q resolvers
if [[ $? == 0 ]]; then
    cat >> $tmpfile <<EOF
    if [ ! -e /etc/resolv.conf ]; then
        echo "# AUTOMATIC ZONE CONFIG" > /etc/resolv.conf
EOF
    zonecfg -z $ZONENAME info attr name=resolvers |
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
    ' >> $tmpfile
    zonecfg -z $ZONENAME info attr name=dns-domain |
    awk '
    {
        if ($1 == "value:") {
            dom = $2
        }
    }
    END {
        printf("        echo \"search %s\" >> %s\n", dom, "/etc/resolv.conf")
    }
    ' >> $tmpfile
    cat >> $tmpfile <<EOF
    fi
    return 0
    }
EOF
else
    cat >> $tmpfile <<EOF
    return 0
    }
EOF
fi

cat >> $tmpfile <<EOF
    stop() {
        return 0
    }
EOF
fnm=$ZONEROOT/etc/init.d/networking
if [[ -f $fnm || -h $fnm ]]; then
	mv -f $tmpfile $fnm
	chmod 755 $fnm
fi


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

#
# Setup for the /dev/shm mount.
#
fnm=$ZONEROOT/etc/fstab
entry=$(awk '{if ($2 == "/dev/shm") print $2}' $fnm)
if [[ -z "$entry" && ! -h $fnm ]]; then
    echo "swapfs    /dev/shm    tmpfs    defaults    0 0" >> $fnm
fi

# Hand control back to lx_boot
