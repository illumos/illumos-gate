#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Copyright 2014 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Customisation for RedHat-based distributions.  Assumes to have been
# sourced from lx_init_zone.
#

enable_nfs_services()
{
	log "Non-miniroot install; enabing NFS servers and NFS lock daemon"

	#
	# Setup files required for NFS:
	#
	#       /native/etc/netconfig
	#       /native/etc/default/nfs
	#
	# These two files are treated as read-only in lx branded zones.
	# To enfore this restriction we will read-only lofs mount them
	# into the zone from the global zone.  For these lofs mounts to
	# work we'll need to create empty directories now that will serve
	# as mount points later.
	#
	#       /sbin/rpc.statd
	#       /sbin/rpc.lockd
	#
	# These files are symlinks to scripts supplied by the lx brand
	# that will start up the solaris nfs daemons.
	#
	if { ! makedir native/etc/netconfig ||
	    ! makedir native/etc/default/nfs ; }; then
		log "Aborting NFS setup..."
		log ""
		return
	fi

	if { ! install_ln ../native/usr/lib/brand/lx/lx_lockd sbin/rpc.lockd ||
	    ! install_ln ../native/usr/lib/brand/lx/lx_statd \
	    sbin/rpc.statd ; }; then
		log "Aborting NFS setup..."
		log ""
		return
	fi

	#
	# update /etc/services for NFS
	#
	log ""
	log "Adding lockd entry to \"$install_root/etc/services\"..."

	cp -p $install_root/etc/services $install_root/etc/services.$tag

	#
	# Brackets in the sed script below contain a space followed by a tab
	#
	cat $install_root/etc/services.$tag |
	    sed 's:\(111\/..p[ 	][ 	]*\):\1rpcbind :' |
	    cat > $install_root/etc/services

	cat >> $install_root/etc/services <<-EOF
	lockd		4045/udp		# NFS lock daemon/manager
	lockd		4045/tcp		# NFS lock daemon/manager
	EOF

	#
	# Modify /etc/init.d/nfslock to enable the USERLAND_LOCKD option and to
	# find some commands in alternate locations.
	#
	log ""
	log "Modifying \"$install_root/etc/init.d/nfslock\"..."
	cp -p etc/init.d/nfslock etc/init.d/nfslock.$tag
	cat etc/init.d/nfslock.$tag |
	    sed '
		s/USERLAND_LOCKD=$/USERLAND_LOCKD="yes"/
		s/killproc rpc.statd/killproc statd/
		s/status rpc.statd/status statd/
		s/pidof rpc.statd/pidof statd/
	    ' |
	    cat > etc/init.d/nfslock
}

#
# The default /etc/inittab spawns mingetty on each of the virtual consoles
# as well as xdm on the X console.  Since we don't have virtual consoles nor
# an X console, spawn a single mingetty on /dev/console instead.
#
# Don't bother changing the file if it looks like we already did.
#
if ! egrep -s "Disabled by lx brand" etc/inittab; then
	log "Modifying: \"$install_root/etc/inittab\"..."

	tmpfile=/tmp/inittab.$$

	sed 's/^[1-6]:/# Disabled by lx brand: &/
	    s/^id:5:initdefault:/id:3:initdefault: # Modified by lx brand: &/' \
	    etc/inittab > $tmpfile

	#
	# Don't bother with further alterations if the sed above failed...
	#
	if [[ $? -eq 0 ]]; then
		egrep -s "console login for lx brand" etc/inittab
		if [[ $? -ne 0 ]]; then
			cat >> $tmpfile <<- EOF

				#
				# console login for lx brand
				#
				1:2345:respawn:/sbin/mingetty console
			EOF

			#
			# Only install the new inittab if the append
			# above succeeded.
			#
			if [[ $? -eq 0 ]]; then
				#
				# Attempt to save off the original inittab
				# before moving over the modified version.
				#
				mv -f etc/inittab etc/inittab.$tag 2>/dev/null

				mv -f $tmpfile etc/inittab

				if [[ $? -ne 0 ]]; then
					log "mv of \"$tmpfile\" to" \
					    "\"$installroot/etc/inittab\"" \
					    "failed!"
					i18n_echo "$cmd2_failed" "mv" \
					    "$tmpfile" \
					    "$installroot/etc/inittab"
					i18n_echo "$install_aborted"
					exit 1
				else
					chmod 644 etc/inittab
				fi
			fi
		fi

	else
		log "Attempt to disable entries in" \
		    "\"$install_root/etc/inittab\" failed!"
		i18n_echo "$disable_failed" "$install_root/etc/inittab"
		i18n_echo "$install_aborted"
		exit 1
	fi
fi

#
# User must configure various brand-specific items to enable networking, so
# boot the system non-networked.
#
log ""
log "Modifying: \"$install_root/etc/sysconfig/network\"..."

mv -f etc/sysconfig/network etc/sysconfig/network.$tag 2>/dev/null

cat > etc/sysconfig/network <<- EOF
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

if [[ $? -ne 0 ]]; then
	log "Could not create new \"$install_root/etc/sysconfig/network\"!"
	i18n_echo "$create_failed" "$install_root/etc/sysconfig/network"
	i18n_echo "$install_aborted"
	exit 1
fi

#
# SELinux must be disabled otherwise we won't get past init.
#
if egrep -s "^SELINUX=enforcing" etc/selinux/config; then
	log "Modifying: \"$install_root/etc/selinux/config\"..."

	tmpfile=/tmp/selinux_config.$$

	sed 's/^SELINUX=enforcing/SELINUX=disabled/' \
	    etc/selinux/config > $tmpfile

	if [[ $? -eq 0 ]]; then
		mv -f etc/selinux/config etc/selinux/config.$tag 2>/dev/null

		mv -f $tmpfile etc/selinux/config

		if [[ $? -ne 0 ]]; then
			log "mv of \"$tmpfile\" to" \
			    "\"$installroot/etc/selinux/config\"" \
			    "failed!"
			i18n_echo "$cmd2_failed" "mv" \
			    "$tmpfile" \
			    "$installroot/etc/selinux/config"
			i18n_echo "$install_aborted"
			exit 1
		else
			chmod 644 etc/selinux/config
		fi
	else
		log "Attempt to disable entries in" \
		    "\"$install_root/etc/selinux/config\" failed!"
		i18n_echo "$disable_failed" "$install_root/etc/selinux/config"
		i18n_echo "$install_aborted"
		exit 1
	fi
fi

if [[ -a etc/sysconfig/syslog ]]; then
	#
	# By default, syslogd will attempt to create a socket in /dev/log, but
	# /dev is not be writable.  Instead, modify /etc/sysconfig/syslog to
	# tell it to use /var/run/syslog instead, and make /dev/log a symlink
	# to /var/run/syslog.
	#
	log ""
	log "Modifying: \"$install_root/etc/sysconfig/syslog\"..."

	tmpfile=/tmp/lx_sc.syslog.$$

	sed 's@\(SYSLOGD_OPTIONS="-m 0\)"@\1 -p /var/run/syslog"@' \
	    etc/sysconfig/syslog > $tmpfile

	#
	# Only install the new sysconfig/syslog if the edit above succeeded.
	#
	if [[ $? -eq 0 ]]; then
		#
		# Attempt to save off the original syslog before moving over
		# the modified version.
		#
		mv -f etc/sysconfig/syslog etc/sysconfig/syslog.$tag 2>/dev/null

		if ! mv -f $tmpfile etc/sysconfig/syslog; then
			log "mv of \"$tmpfile\" to" \
			    "\"$installroot/etc/sysconfig/syslog\" failed!"
			i18n_echo "$cmd2_failed" "mv" "$tmpfile" \
			    "$installroot/etc/sysconfig/syslog"
			i18n_echo "$install_aborted"
			exit 1
		else
			chmod 755 etc/sysconfig/syslog
		fi
	else
		log "Attempt to modify entries in" \
		    "\"$install_root/sysconfig/syslog\" failed!"
		i18n_echo "$mod_failed" "$install_root/sysconfig/syslog"
		i18n_echo "$install_aborted"
		exit 1
	fi
fi

if [[ $? -ne 0 ]]; then
	log "Could not create new \"$install_root/etc/sysconfig/syslog\"!"
	i18n_echo "$create_failed" "$install_root/etc/sysconfig/syslog"
	i18n_echo "$install_aborted"
	exit 1
fi

#
# /etc/rc.d/init.d/keytable tries to load a physical keyboard map, which won't
# work in a zone. If we remove etc/sysconfig/keyboard, it won't try this at all.
#
mv -f etc/sysconfig/keyboard etc/sysconfig/keyboard.$tag 2>/dev/null

#
# /etc/rc.d/init.d/gpm tries to configure the console mouse for cut-and-paste
# text operations, which we don't support.  Removing this file disables the
# mouse configuration.
#
mv -f etc/sysconfig/mouse etc/sysconfig/mouse.$tag 2>/dev/null

#
# The following scripts attempt to start services or otherwise configure
# the system in ways incompatible with zones, so don't execute them at boot
# time.
#
log ""
log "Modifying \"$install_root/etc/rc.d/init.d\" to disable any"
log "  services not supported by BrandZ:"
unsupported_services="
	kudzu
	microcode_ctl
	network
	random
        pcmcia
	isdn
	iptables
	ip6tables
	iscsi
	psacct
	gpm
	irda
	smartd
	rawdevices
	netdump
	hpoj
	mdmonitor
	mdmpd
	irqbalance
"

for file in $unsupported_services; do
	if [[ -a "etc/rc.d/init.d/$file" ]]; then

	    if mv -f "etc/rc.d/init.d/$file" "etc/rc.d/init.d/$file.$tag"; then
		    log "    + Moved script \"etc/rc.d/init.d/$file\" to"
		    log "          \"etc/rc.d/init.d/$file.$tag\""
	    fi
	fi

	rc_files="$(echo etc/rc.d/rc[0-6].d/[SK]+([0-9])$file)"

	if [[ "$rc_files" != "etc/rc.d/rc[0-6].d/[SK]+([0-9])$file" ]]; then
		for file in $rc_files; do
			if [[ -h "$file" ]]; then
				rm -f "$file" &&
				    log "    + Removed symbolic link \"$file\""
			else
				rm -f "$file" &&
				    log "    + Removed script \"$file\""
			fi
		done
	fi
done

#
# There is a lot of stuff in the standard halt and reboot scripts that we
# have no business running in a zone.  Fortunately, the stuff we want to
# skip is all in one contiguous chunk.
#
# Don't bother to modify the file if it looks like we already did.
#
if ! egrep -s "Disabled by lx brand" etc/rc.d/init.d/halt; then
	log ""
	log "Modifying  \"$install_root/etc/rc.d/init.d/halt\" for operation"
	log "  within a zone..."
	awk 'BEGIN {skip = ""}
	    /^# Save mixer/ {skip = "# Disabled by lx brand: "}
	    /halt.local/ {skip = ""}
	    /./ {print skip $0}' etc/rc.d/init.d/halt > /tmp/halt.$$

	if [[ $? -eq 0 ]]; then
		mv -f etc/rc.d/init.d/halt etc/rc.d/init.d/halt.$tag 2>/dev/null
		mv -f /tmp/halt.$$ etc/rc.d/init.d/halt
		chmod 755 etc/rc.d/init.d/halt
	else
		log "Attempt to modify \"$install_root/etc/rc.d/init.d/halt\"" \
		    "FAILED"
		log "Continuing with balance of zone setup..."
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
if ! egrep -s "Disabled by lx brand" etc/rc.d/rc.sysinit; then
	log ""
	log "Modifying: \"$install_root/etc/rc.d/rc.sysinit\"..."
	log ""

	tmpfile=/tmp/lx_rc.sysinit.$$

	sed 's@^/sbin/hwclock@# Disabled by lx brand: &@
	    s@^HOSTTYPE=@HOSTTYPE=\"s390\" # Spoofed for lx brand: &@
	    s@/bin/dmesg -n@: # Disabled by lx brand: &@
	    s@^dmesg -s@# Disabled by lx brand: &@
	    s@initlog -c \"fsck@: # Disabled by lx brand: &@
	    s@^.*mount .* /dev/pts$@# Disabled by lx brand: &@' \
	    etc/rc.d/rc.sysinit > $tmpfile

	#
	# Only install the new rc.sysinit if the edit above succeeded.
	#
	if [[ $? -eq 0 ]]; then
		#
		# Attempt to save off the original rc.sysinit
		# before moving over the modified version.
		#
		mv -f etc/rc.d/rc.sysinit etc/rc.d/rc.sysinit.$tag 2>/dev/null

		if ! mv -f $tmpfile etc/rc.d/rc.sysinit; then
			log "mv of \"$tmpfile\" to" \
			    "\"$installroot/etc/rc.d/rc.sysinit\" failed!"
			i18n_echo "$cmd2_failed" "mv" "$tmpfile" \
			    "$installroot/etc/rc.d/rc.sysinit"
			i18n_echo "$install_aborted"
			exit 1
		else
			chmod 755 etc/rc.d/rc.sysinit
		fi
	else
		log "Attempt to modify entries in" \
		    "\"$install_root/rc.d/rc.sysinit\" failed!"
		i18n_echo "$mod_failed" "$install_root/rc.d/rc.sysinit"
		i18n_echo "$install_aborted"
		exit 1
	fi
fi

if [[ -z $is_miniroot ]]; then
	enable_nfs_services || log "NFS services were not properly enabled."
fi

# Hand control back to lx_init_zone
