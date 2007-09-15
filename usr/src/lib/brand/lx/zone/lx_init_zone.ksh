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
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# This script contains various routines used to post-process a zone for use
# with BrandZ after it has been installed from RPM media or a tar image.
#
# Briefly, there are three main jobs we need to do:
#
# 1) Create any needed directories and symlinks BrandZ needs but that the
#    Linux install may not create
#
# 2) Modify rc scripts to shut off services that don't apply to a zone
#    or that wish to access hardware directly
#
# 3) Modify various Linux system files for use within a zone environment
#

#
# Restrict executables to /bin and /usr/bin
#
PATH=/bin:/usr/bin
export PATH

#
# Sends output to a log file via redirection of stderr.
#
# This script assumes its caller has already performed the redirection to the
# logfile.
#
log()
{
        echo "$@" >&2
}

#
# Setup i18n output
#
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

cmd_failed=$(gettext "%s failed!  Aborting installation...")
cmd2_failed=$(gettext "%s of '%s' to '%s' failed!")
create_failed=$(gettext "Could not create new file '%s'!")
disable_failed=$(gettext "Attempt to disable entries in '%s' failed!")
install_aborted=$(gettext "Aborting installation...")
install_noroot=$(gettext "Installation root directory '%s' does not exist.")
ln_fail=$(gettext "Unable to symlink '%s' to '%s'!")
mkdir_fail=$(gettext "Unable to create the directory '%s'")
mod_failed=$(gettext -n "Attempt to modify entries in '%s' failed!")

usage=$(gettext "usage: %s <install_root> [mini]")

#
# Output an internationalized string followed by a carriage return
#
i18n_echo()
{
	typeset fmt="$1"
	shift

	printf "$fmt\n" "$@"
}

#
# Routine to make a full path out of a supplied path
#
fullpath()
{
	typeset path="$1"

	echo $path | egrep -s "^/" || path="${PWD:=$(pwd)}/$path"
	echo $path
}

#
# Routine to create directories and handle errors
#
makedir()
{
	typeset dirname=$(fullpath "$1")
	typeset mode=""

	[[ $# -eq 2 ]] && mode="-m $2"

	[[ -d "$dirname" ]] && return

	if ! mkdir $mode -p "$dirname"; then
		log "Unable to create the directory \"$dirname\"!"
		i18n_echo "$mkdir_fail" "$dirname"
		echo $(gettext "Aborting installation...")
		exit 1
	fi
}

#
# Routine to create initial symlinks and handle errors
#
symlink()
{
	typeset src="$1"
	typeset dst=$(fullpath "$2")

	[[ -e "$dst" || -h "$dst" ]] && rm -f "$dst"
	
	if ! ln -s "$src" "$dst"; then
		log "Unable to symlink \"$src\" to \"$dst\"!"
		i18n_echo "$ln_fail" "$src" "$dst"
		echo $(gettext "Aborting installation...")
		exit 1
	fi
}

#
# Install a file using "ln -s"
#
# Returns 0 on success, 1 on failure.
#
install_ln()
{
	typeset source="$1"
	typeset target=$(fullpath "$2")

	log "    Installing \"$target\""

	mv -f "$target" "$target.$tag" 2>/dev/null

	if ! ln -s "$source" "$target"; then
		log ""
		log "Attempt to install $target FAILED."
		return 1
	fi

	return 0
}


#
# Enable NFS servers and the NFS lock daemon for a particular zone.
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
# The main script starts here.
#
# The syntax is:
#
#     lx_init_zone <rootdir> [mini]
#
# Where:
#	<rootdir> is the root of the zone directory to be modified
#
#	[mini]	is an optional second argument that signifies whether this is
#		to be a miniroot install; if it is, NFS services are not enabled
#		in the processed zone
#
unset is_miniroot
unset install_root

install_root="$1"

tag="lxsave_$(date +%m.%d.%Y@%T)"

if (($# < 1 || $# > 2)); then
	i18n_echo "$usage" "$0"
	exit 1
fi

(($# == 2)) && is_miniroot=1

if [[ ! -d "$install_root" ]]; then
	i18n_echo "$install_noroot" "$install_root"
	echo $(gettext "** Installation aborted **")
	exit 1
fi

cd "$install_root"

log ""
log "Initial lx_brand environment modification started `date`"
log "Making needed directories in \"$install_root\"."
echo $(gettext "Setting up the initial lx brand environment.")

#
# Make various directories in /native that are needed to boot an lx branded
# zone.
#
makedir native/dev
makedir native/etc/default
makedir native/etc/svc/volatile
makedir native/lib
makedir native/proc
makedir native/tmp 1777
makedir native/usr
makedir native/var

#
# Make various other directories needed for the lx brand
#
makedir mnt
makedir opt
makedir usr/local/bin
makedir usr/local/include
makedir usr/local/lib
makedir usr/local/sbin
makedir usr/local/share
makedir usr/local/src

makedir dev 0755
makedir tmp 1777
makedir proc 0555
makedir boot 0755

#
# zlogin requires that these utilities live in places other than their
# Linux defaults, so create appropriate links for them here.
#
# XX - The need for these links may go away in the future if zlogin is
#      appropriately modified
#
symlink /bin/sh sbin/sh
symlink /bin/su usr/bin/su
symlink /native/usr/lib/ld.so.1 usr/lib/ld.so.1

libpam_so="$(echo lib/libpam.so.0.*)"
libpam_misc="$(echo lib/libpam_misc.so.0.*)"
libpamc_so="$(echo lib/libpamc.so.0.*)"

symlink "/$libpam_so" lib/libpam.so.0
symlink "/$libpam_misc" lib/libpam_misc.so.0
symlink "/$libpamc_so" lib/libpamc.so.0

log ""
log "Modifying system configuration in \"$install_root\""

#
# Create a /var/ld/ld.config that will point to /native/lib for our Solaris
# libraries.
#
log "Creating \"$install_root/var/ld/ld.config\"..."

makedir var/ld

if ! crle -c var/ld/ld.config -l /native/lib:/native/usr/lib \
     -s /native/lib/secure:/native/usr/lib/secure; then
	log "\tCreation of \"$install_root/var/ld/ld.config\" failed!"
	i18n_echo "$cmd_failed" "crle"
	exit 1
fi

log ""
log "Modifying \"$install_root/etc/fstab\"..."

mv -f etc/fstab etc/fstab.$tag 2>/dev/null

cat > etc/fstab <<- EOF
	none		/			ufs	defaults	1 1
	none		/proc			proc	defaults	0 0
EOF

if [[ $? -ne 0 ]]; then
	log "Could not create new \"$install_root/etc/fstab\"!"
	i18n_echo "$create_failed" "$install_root/etc/fstab"
	exit 1
fi

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

if [[ ! -e "$install_root/etc/hosts" ]]; then
	log ""
	log "Creating: \"$install_root/etc/hosts\"..."

	cat > "$install_root/etc/hosts" <<-_EOF_
		127.0.0.1		localhost
	_EOF_
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

log ""
log "System configuration modifications complete `date`"
log ""
i18n_echo "System configuration modifications complete."
exit 0
