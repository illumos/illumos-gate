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
# Customisation for Debian-based distributions.  Assumes to have been
# sourced from lx_init_zone.
#


#
# The default /etc/inittab spawns getty on each of the virtual consoles
# as well as xdm on the X console.  Since we don't have virtual consoles nor
# an X console, spawn a single getty on /dev/console instead.
#
# Don't bother changing the file if it looks like we already did.
#
if [[ -f etc/inittab ]] && ! egrep -s "Disabled by lx brand" etc/inittab; then
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
				1:2345:respawn:/sbin/getty 115200 console
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
# Stop rsyslogd logging to /dev/xconsole, we cannot create it and it is
# unlikely to be useful in our environment.
#
if sed -n 115p etc/rsyslog.conf | egrep -s "^	.*\|/dev/xconsole"; then
	log ""
	log "Modifying: \"$install_root/etc/rsyslog.conf\"..."

	tmpfile=/tmp/lx_rsyslog.conf.$$

	sed -e '111,115s/^/# Disabled by lx brand/' \
	    etc/rsyslog.conf > $tmpfile

	if [[ $? -eq 0 ]]; then
		mv -f etc/rsyslog.conf etc/rsyslog.conf.$tag 2>/dev/null

		if ! mv -f $tmpfile etc/rsyslog.conf; then
			log "mv of \"$tmpfile\" to" \
			    "\"$installroot/etc/rsyslog.conf\" failed!"
			i18n_echo "$cmd2_failed" "mv" "$tmpfile" \
			    "$installroot/etc/rsyslog.conf"
			i18n_echo "$install_aborted"
			exit 1
		fi
	else
		log "Attempt to modify entries in" \
		    "\"$install_root/sysconfig/syslog\" failed!"
		i18n_echo "$mod_failed" "$install_root/sysconfig/syslog"
		i18n_echo "$install_aborted"
		exit 1
	fi
fi
if grep "^	create_xconsole" etc/init.d/rsyslog >/dev/null 2>&1; then
	log ""
	log "Modifying: \"$install_root/etc/init.d/rsyslog\"..."

	tmpfile=/tmp/lx_init_rsyslog.$$

	sed -e '/^	create_xconsol/s/^/# Disabled by lx brand/' \
	    etc/init.d/rsyslog > $tmpfile

	if [[ $? -eq 0 ]]; then
		mv -f etc/init.d/rsyslog etc/init.d/rsyslog.$tag 2>/dev/null

		if ! mv -f $tmpfile etc/init.d/rsyslog; then
			log "mv of \"$tmpfile\" to" \
			    "\"$installroot/etc/init.d/rsyslog\" failed!"
			i18n_echo "$cmd2_failed" "mv" "$tmpfile" \
			    "$installroot/etc/init.d/rsyslog"
			i18n_echo "$install_aborted"
			exit 1
		else
			chmod 755 etc/init.d/rsyslog
		fi
	else
		log "Attempt to modify entries in" \
		    "\"$install_root/sysconfig/syslog\" failed!"
		i18n_echo "$mod_failed" "$install_root/sysconfig/syslog"
		i18n_echo "$install_aborted"
		exit 1
	fi
fi

#
# The following scripts attempt to start services or otherwise configure
# the system in ways incompatible with zones, so don't execute them at boot
# time.
#
log ""
log "Modifying \"$install_root/etc/init.d\" to disable any"
log "  services not supported by BrandZ:"
unsupported_services="
	bootmisc.sh
	checkroot.sh
	hwclock.sh
	hwclockfirst.sh
	mountdevsubfs.sh
	mountkernfs.sh
	mtab.sh
	networking
	umountfs
"

for file in $unsupported_services; do
	if [[ -e "etc/init.d/$file" ]]; then

	    if mv -f "etc/init.d/$file" "etc/init.d/$file.$tag"; then
		    log "    + Moved script \"etc/init.d/$file\" to"
		    log "          \"etc/init.d/$file.$tag\""
	    fi
	fi

	rc_files="$(echo etc/rc[S0-6].d/[SK]+([0-9])$file)"

	if [[ "$rc_files" != "etc/rc[0-6].d/[SK]+([0-9])$file" ]]; then
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
# udev isn't usable within the zone
#
if [[ -e "sbin/udevd" ]]; then
    if mv -f "sbin/udevd" "sbin/udevd.$tag"; then
        log "    + Moved \"sbin/udevd\" to \"sbin/udevd.$tag\""
    fi
fi

#
# Fix mountall
#
if [ -f etc/init.d/mountall.sh ]; then
	tmpfile=etc/init.d/mountall.$$
	sed 's/mount_run/# disabled for lx brand: &/
	     s/mount_shm/# disabled for lx brand: &/
	     s/mount_tmp/# disabled for lx brand: &/
	     s/pidof \/sbin\/init/false/
	    ' etc/init.d/mountall.sh > $tmpfile
	mv -f $tmpfile etc/init.d/mountall.sh
	chmod +x etc/init.d/mountall.sh
fi

ip_stack_type=`/usr/sbin/zonecfg -z $zonename info ip-type | cut -d' ' -f2`
if [[ "$ip_stack_type" == "exclusive" ]]; then
	# We already moved aside the 'networking' service in the code
	# above. Setup our own service which will configure the net.
	cp /usr/lib/brand/lx/lx_networking etc/init.d/networking
fi

if [[ $distro == "debian" ]]; then
	# No upstart, setup rc link
	ln -s ../init.d/networking etc/rcS.d/S10networking

# else  must be Ubuntu, so upstart.

fi

if [[ -f etc/mtab ]]; then
	log "Modifying: \"$install_root/etc/mtab\"..."

	echo "/ / zfs rw 0 0" > etc/mtab
	echo "proc /proc proc rw,noexec,nosuid,nodev 0 0" >> etc/mtab
fi

# Hand control back to lx_init_zone
