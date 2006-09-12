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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

#
# This script is called from /usr/lib/brand/lx/lx_install.
# 
# options passed down from lx_install:
#	-z $ZONENAME
#	-r $LINUX_ROOT
#
# options passed down from zoneadm -z <zone-name> install
#	-d <Linux-archives-dir>
#	[core | server | desktop | development | all]
#
# The desktop cluster will be installed by default.
#

#
# Restrict executables to /bin, /usr/bin and /usr/sbin
#
PATH=/bin:/usr/bin:/usr/sbin
export PATH


#
# Setup i18n output
#
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

#
# Log passed arguments to file descriptor 2
#
log()
{
	[[ -n $logfile ]] && echo "$@" >&2
}

#
# Send the provided printf()-style arguments to the screen and to the
# logfile.
#
screenlog()
{
	typeset fmt="$1"
	shift

	printf "$fmt\n" "$@"
	[[ -n $logfile ]] && printf "$fmt\n" "$@" >&2
}

#
# Print and log provided text if the shell variable "verbose_mode" is set
#
verbose()
{
	[[ -n $verbose_mode ]] && echo "$@"
	[[ -n $logfile ]] && [[ -n $verbose_mode ]] && echo "$@" >&2
}

no_space=$(gettext "Not enough free space available in '%s'")
mb_req=$(gettext "(%s MB required, %s MB available)")
bad_rpmdir=$(gettext "'%s' is not a valid RPM directory!")

inst_clust=$(gettext "Installing cluster '%s'")
unknown_clust=$(gettext "ERROR: Unknown cluster name: '%s'")

wrong_disk=\
$(gettext "Incorrect disk inserted (found %s, wanted %s), ejecting...")

lofs_failed=$(gettext "Attempt to lofs mount '%s' on '%s' FAILED.")
symlink_failed=$(gettext "Attempt to symbolically link '%s' to '%s' FAILED.")

mini_discfail=$(gettext "Install of zone '%s' miniroot from disc %s FAILED.")
mini_isofail=$(gettext "Install of zone '%s' miniroot from ISO '%s' FAILED.")

mini_initfail=$(gettext "Attempt to initialize miniroot for zone '%s' FAILED.")
mini_instfail=$(gettext "Attempt to install miniroot for zone '%s' FAILED.")
mini_rpmfail=$(gettext "Miniroot install of RPM '%s' FAILED.")
mini_copyfail=$(gettext "Attempt to copy miniroot for zone '%s' FAILED.")
mini_bootfail=$(gettext "Attempt to boot miniroot for zone '%s' FAILED.")
mini_setfail=$(gettext "Attempt to setup miniroot for zone '%s' FAILED.")

mini_mntfsfail=\
$(gettext "Attempt to mount miniroot filesystems for zone '%s' FAILED.")

rpm_initfail=\
$(gettext "Attempt to initialize RPM database for zone '%s' FAILED.")

zone_initrootfail=\
$(gettext "Attempt to initialize root filesystem for zone '%s' FAILED.")

zone_discfail=$(gettext "Install of zone '%s' from disc %s FAILED.")
zone_isofail=$(gettext "Install of zone '%s' from ISO '%s' FAILED.")
zone_instfail=$(gettext "Install of zone '%s' from '%s' FAILED '%s'.")
zone_haltfail=$(gettext "Unable to halt zone '%s'!")

zone_rootfail=\
$(gettext "ERROR: The specified zone root directory '%s' could not be created.")

zone_rootsub=\
$(gettext "ERROR: The specified zone root subdirectory '%s' does not exist.")

mk_mntfail=$(gettext "Could not create the mount directory '%s'")
iso_mntfail=$(gettext "Unable to mount ISO image '%s' within zone '%s'")
iso_umntfail=$(gettext "Unable to unmount ISO image '%s' from within zone '%s'")
mountfail=$(gettext "Mount of '%s' on '%s' FAILED.")

insert_discmsg=\
$(gettext "Please insert disc %s in the removable media drive and press")

install_discmsg=$(gettext "Installing zone '%s' from disc %s.")
install_isomsg=$(gettext "Installing zone '%s' from ISO image %s.")
install_ndiscs=$(gettext "You will need discs 1 - %s to fully install ")

expand_nrpms=$(gettext "Attempting to expand %s RPM names...")

install_nrpms_few=\
$(gettext "Installing %s RPM packages; this may take a few minutes...")
install_nrpms_several=\
$(gettext "Installing %s RPM packages; this may take several minutes...")

install_zonefail=$(gettext "Attempt to install zone '%s' FAILED.")
install_dist=$(gettext "Installing distribution '%s'...")

log_wrfail=$(gettext "Error: cannot write to log file '%s'.")

no_distropath=$(gettext "ERROR: Distribution path '%s' doesn't exist.")

initinstall_zonefail=$(gettext "Initial installation of zone '%s' FAILED.")

install_abort=$(gettext "Installation aborted %s")
install_done=$(gettext "Initial installation of zone '%s' complete %s")

#
# Get the device underlying a specified mounted file system
#
# Returns 0 on success, 1 on failure.
#
get_mountdev()
{
	typeset mount_dir="$1"
	typeset device
	unset mount_dev

	device="`{ df -k "$mount_dir" | egrep "^/" ; } 2>/dev/null`" || return 1
	mount_dev=$(echo $device | awk -e '{print $1}' 2>/dev/null)

	[[ "`echo $mount_dev | cut -c 1`" = "/" ]] && return 0

	unset mount_dev
	return 1
}

#
# Get the directory name a specified device is mounted as
#
# Returns 0 on success, 1 on failre.
#
get_mountdir()
{
	typeset mount_dev="$1"
	typeset dir
	unset mount_dir

	dir="`{ df -k "$mount_dev" | egrep "^/" ; } 2>/dev/null`" || return 1
	mount_dir=$(echo $dir | awk -e '{print $6}' 2>/dev/null)

	[[ "`echo $mount_dir | cut -c 1`" = "/" ]] && return 0

	unset mount_dir
	return 1
}

#
# Check the free disk space of the passed filesystem against the passed
# argument.
#
# Returns 0 on success, 1 on failure.
#
check_mbfree()
{
	typeset dir="$1"
	typeset mb_required=$2

	#
	# Return free space in partition containing passed argument in MB
	#
	typeset mbfree=`( df -k "$dir" 2>/dev/null | \
	    egrep -v Filesystem | awk -e '{print $4}' ) 2>/dev/null` || return 1

	((mbfree /= 1024))
	if ((mbfree < mb_required)); then
		screenlog "$no_space" "$zoneroot"
		screenlog "$mb_req" "$mb_required" "$mb_free"
		return 1
	fi
	return 0
}

#
# Expand passed RPM names to their appropriate filenames in the passed RPM
# directory.
#
# Arguments:
#
#	Argument 1:  Mounted CD-ROM/ISO directory
#	Argument 2:  RPM directory
#	Arguments [3 - n]: RPM names to process
#
# The expanded RPM names are returned in the shell array "rpm_names."
#
# For example:
#
#	expand_rpm_names /mnt/iso RedHat/RPMS dev kernel tetex redhat-menus
#
# would return something like:
#
#	rpms_found[0]:  dev-3.3.12.3-1.centos.0.i386.rpm
#	rpms_found[1]:  kernel-2.4.21-32.EL.i586.rpm
#	rpms_found[2]:  tetex-1.0.7-67.7.i386.rpm
#	rpms_found[3]:  redhat-menus-0.39-1.noarch.rpm
#
# The routine returns 0 on success, 1 on an error.
#
expand_rpm_names()
{
	typeset found=0
	typeset left=0

	typeset rpmdir="$1/$2"
	typeset curdir=${PWD:=$(pwd)}

	typeset arch
	typeset procinfo
	typeset rpmglob
	typeset rpmfile

	unset rpms_found
	unset rpms_left

	shift; shift
	cd "$rpmdir"

	typeset rpmcheck="$(echo *.rpm)"

	if [[ "$rpmcheck" = "*.rpm" ]]; then
		screenlog "$bad_rpmdir" "$rpmdir"
		cd "$curdir"
		return 1
	fi

	#
	# If the miniroot is booted, and the archs list isn't already set,
	# ask the zone's rpm command for the list of compatible architectures.
	#
	if [[ -n $miniroot_booted && -z $archs ]]; then
		procinfo=$(zlogin "$zonename" /bin/rpm --showrc | \
		    grep "^compatible archs")

		[[ $? -eq 0 ]] &&
		    archs=$(echo $procinfo | sed -e 's/^compatible archs : //')

		[[ -n $archs ]] &&
		    log "RPM-reported compatible architectures: $archs"
	fi

	#
	# Either the miniroot isn't booted or asking rpm for the information
	# failed for some reason, so make some reasonable assumptions.
	#
	if [[ -z $archs ]]; then
		procinfo=$(psrinfo -vp | grep family)

		if echo "$procinfo" | egrep -s "AuthenticAMD"; then
			#
			# Check for AMD athlon compatibility.  The decision to
			# have athlon files checked for before i686 files is
			# what Linux does.
			#
			if echo "$procinfo" | egrep -s "family 6" ||
			    echo "$procinfo" | egrep -s "family 15"; then
				archs="athlon i686"
			fi
		elif echo "$procinfo" | egrep -s "GenuineIntel"; then
			#
			# Check for i686 compatibility
			#
			if echo "$procinfo" | egrep -s "family 15"; then
				archs="i686"
			fi
		fi

		archs="$archs i586 i486 i386 noarch"

		log "Derived compatible architectures: $archs"
	fi

	verbose "RPM source directory: \"$rpmdir\""
	log "RPM source directory: \"$rpmdir\""

	if [[ $# -eq 1 ]]; then
		screenlog "$(gettext 'Attempting to expand 1 RPM name')"
	else
		screenlog "$expand_nrpms" "$#"
	fi

	for rpm in "$@"; do
		#
		# Search for the appropriate RPM package, using the compatible
		# architecture list contained in "archs" to look for the best
		# match.
		#
		# For example, if the processor is an i686, and the rpm is
		# "glibc", the script will look for the files (in order):
		#
		#    glibc[.-][0-9]*.i686.rpm
		#    glibc[.-][0-9]*.i586.rpm
		#    glibc[.-][0-9]*.i486.rpm
		#    glibc[.-][0-9]*.i386.rpm
		#    glibc[.-][0-9]*.noarch.rpm
		#    glibc[.-][0-9]*.fat.rpm
		#
		# and will stop when it finds the first match.
		#
		# TODO: Once the miniroot is booted, we should verify that
		#	the rpm name has been expanded to "$rpmfile" properly
		#	by comparing "$rpm" and the output of:
		#
		#	zlogin -z <zone> /bin/rpm --qf '%{NAME}' -qp $rpmfile
		#
		for arch in $archs; do
			rpmglob="$rpm[.-][0-9]*.$arch.rpm"
			rpmfile="$(echo $rpmglob)"

			[[ "$rpmfile" != "$rpmglob" ]] && break

			unset rpmfile
                done

                if [[ -z $rpmfile ]]; then
			rpms_left[$left]="$rpm"
			((left += 1))
                else
                        rpms_found[$found]="$rpmfile"
			((found += 1))
                fi
	done

	cd "$curdir"
	log "\"$rpmdir\": matched $found of $# RPM names."
	log "\"$rpmdir\": $left RPMs remaining."
	return 0
}

#
# Build the rpm lists used to install a machine.
#
# The first argument is the number of discs in the distribution.  The
# second, optional, argument is the metacluster to install.
#
# The array "distro_rpm[]" is built from the individual package RPM arrays
# read in from an individual distribution definition file.
#
build_rpm_list()
{
	# Default to a desktop installation
	typeset cluster=desktop
	typeset cnt=0
	typeset pkgs

	for clust in "$@"; do
		((cnt += 1))
		case $clust in
			core)	cluster=core ;;
			desk*)	cluster=desktop ;;
			serv*)	cluster=server ;;
			dev*)	cluster=developer ;;
			all)	cluster=all
				break;;
			*)      screenlog "$unknown_clust" "$clust"
				exit $ZONE_SUBPROC_USAGE ;;
		esac
	done

	if [ $cnt -gt 1 ]; then
		screenlog "$(gettext 'Too many install clusters specified')"
		exit $ZONE_SUBPROC_USAGE
	fi

	screenlog "$inst_clust" $cluster

	case $cluster in
		core)		distro_rpms=$distro_core_rpms ;;
		desktop)	distro_rpms=$distro_desktop_rpms ;;
		server)		distro_rpms=$distro_server_rpms ;;
		developer)	distro_rpms=$distro_developer_rpms ;;
		all)		distro_rpms=$distro_all_rpms ;;
	esac

	# The RPMs in the miniroot must all be installed properly as well
	distro_rpms="$distro_miniroot_rpms $distro_rpms"
}

#
# Install the "miniroot" minimal Linux environment that is booted single-user
# to complete the install.
#
# This works by doing feeding the RPM list needed for the installation one
# by one to rpm2cpio(1).
#
# Usage:
#    install_miniroot <mounted media dir> <RPM directory> <RPMS to install>
#      
#
install_miniroot()
{
        typeset mediadir="$1"
	typeset rpmdir="$2"
	typeset rpm

	shift; shift

        for rpm in "$@"; do
		verbose "Installing RPM \"$rpm\" to miniroot at" \
			"\n    \"$zoneroot\"..."

		rpm2cpio "$mediadir/$rpmdir/$rpm" | \
		    ( cd "$rootdir" && cpio -idu ) 1>&2

		if [[ $? -ne 0 ]]; then
			screenlog "$mini_instfail" "$rpm"
			return 1
		fi
        done

	return 0
}

#
# Install the zone from the mounted disc image by feeding a list of RPMs to
# install from this image to RPM running on the zone via zlogin(1).
#
# Usage:
#    install_zone <root dir> <RPM directory> <RPMS to install>
#
install_zone()
{
	#
	# convert media directory to zone-relative path
	#
	typeset zonerpmdir=${1##$rootdir}/$2
	typeset rpmopts="-i"

	typeset rpmerr

	shift; shift

	[[ -n $verbose_mode ]] && rpmopts="-ivh"

	#
	# There's a quirk in our version of ksh that sometimes resets the
	# trap handler for the shell.  Since the rpm command will be the
	# longest part of any given install, make sure that an interrupt while
	# the command is running will bring the miniroot down and clean up
	# the interrupted install.
	#
	trap trap_cleanup INT

	#
	# Print a message depending on how many RPMS we have to install.
	#
	# Ten RPMS seems like a reasonable boundary between when an install may
	# take a "few" or "several" minutes.
	#
	if [[ $# -eq 1 ]]; then
		screenlog "$(gettext 'Installing 1 RPM package.')"
	elif [[ $# -lt 10 ]]; then
		screenlog "$install_nrpms_few" "$#"
	else
		screenlog "$install_nrpms_several" "$#"
	fi

	log ""
	log "Installing: $@"
	log ""

	echo

	#
	# LX_INSTALL must be defined when running this command in order to
	# enable switches built into various emulated system calls to allow
	# the dev package (which may not actually write to /dev) to function.
	#
	zlogin "$zonename" "( cd "$zonerpmdir" ; LX_INSTALL=1 \
	    /bin/rpm $rpmopts --force --aid --nosignature --root /a $@ )"

	rpmerr=$?

	if [[ $rpmerr -ne 0 ]]; then
		log ""
		log "Zone RPM install exited, code $rpmerr"
		log ""

		screenlog "$zone_instfail" "$zonename" "$zonerpmdir" "$rpmerr"
		return 1
	fi

	return 0
}

#
# Attempt to unmount all file systems passed on the command line
#
# Returns 0 if all umounts succeeded, otherwise the number of umount failures
#
umount_list()
{
	typeset failures=0
	typeset mounted

	unset umount_failures

	for mounted in "$@"; do
		if ! umount "$mounted"; then
			umount_failures="$umount_failures $mounted"
			((failures += 1))
		fi
	done

	return $failures
}

#
# Set up lofi mounts required for chroot(1M) to work on a new root directory
# located in /a within a zone.
#
newroot_lofimnt()
{
	typeset dev
	typeset mounted
	typeset target

	unset newroot_mounted

	#
	# /usr and /lib get lofs mounted in the zone on /native read-only
	#
	# $zoneroot/dev gets lofs mounted on /native/dev read/write to allow
	# the use of native devices.
	#
	mount -F lofs -o ro /lib "$rootdir/a/native/lib" || return 1
	newroot_mounted="$rootdir/a/native/lib"

	if ! mount -F lofs -o ro /usr "$rootdir/a/native/usr"; then
		umount "$rootdir/a/native/lib"
		unset newroot_mounted
		return 1
	fi

	newroot_mounted="$newroot_mounted $rootdir/a/native/usr"

	if ! mount -F lofs "$zoneroot/root/native/dev" \
	    "$rootdir/a/native/dev"; then
		umount_list $newroot_mounted
		unset newroot_mounted
		return 1
	fi

	newroot_mounted="$newroot_mounted $rootdir/a/native/dev"

	#
	# This is a bit ugly; to provide device access within the chrooted
	# environment RPM will use for its install, we will create the same
	# symlinks "$rootdir/dev" contains in the new dev directory, and will
	# lofs mount the balance of "$rootdir/dev" into the same locations in
	# /dev in the new filesystem we're installing to.
	#
	for dev in "$zoneroot"/root/dev/*
	do
		if [[ "$dev" == "$zoneroot/root/dev/*" ]]; then
			log "ERROR: No files found in $zoneroot/root/dev"
			umount_list $newroot_mounted
			return 1
		fi

		target="$rootdir/a/dev/$(basename $dev)"

		#
		# If the device file is a symbolic link, create a new link
		# in the target directory with the same source.
		#
		# If the device file is any other file or directory, lofs
		# mount it from the device directory into the target directory.
		#
		if [[ -h $dev ]]; then
			typeset source=$(LC_ALL=C; file -h "$dev")

			#
			# Remove extraneous text from the output of file(1) so
			# we're left only with the target path of the symbolic
			# link.
			#
			source="${source##*link to }"

			[[ -a "$target" ]] && /bin/rm -f "$target"

			if ! ln -s "$source" "$target"; then
				screenlog "$symlink_failed" "$source" "$target"
				umount_list $newroot_mounted
				unset newroot_mounted
				return 1
			fi
		else
			[[ ! -a "$target" ]] && touch "$target"

			if ! mount -F lofs "$dev" "$target"; then
				screenlog "$lofs_failed" "$dev" "$target"
				umount_list $newroot_mounted
				unset newroot_mounted
				return 1
			fi

			newroot_mounted="$newroot_mounted $target"
		fi

	done

	return 0
}

#
# Replace the root directory of a zone with the duplicate previously created
# in the zone's /a directory.
#
replace_miniroot()
{
	#
	# The zoneadm halt will automatically unmount any file systems
	# mounted via lofs in the zone, so that saves us from having to
	# methodically unmount each one.
	#
	if ! zoneadm -z "$zonename" halt; then
		screenlog "$zone_haltfail" "$zonename"
		return 1
	fi

	unset miniroot_booted
	unset newroot_mounted

	[[ -d "$zoneroot/a" ]] && rm -rf "$zoneroot/a"
	[[ -d "$zoneroot/oldroot" ]] && rm -rf "$zoneroot/oldroot"

	#
	# Copy the logfile or we'll lose all details of the install into the
	# new root directory, so strip "$zoneroot" off the pathname of the
	# current logfile and use it to generate the pathname of the log file
	# in the new root directory.
	#
	[[ -n $logfile && -f "$logfile" ]] &&
	    cp "$logfile" "$rootdir/a${logfile##$rootdir}"

	mv -f "$rootdir/a" "$zoneroot/a" || return 1
	mv -f "$rootdir" "$zoneroot/oldroot" || return 1
	mv -f "$zoneroot/a" "$rootdir" || return 1

	screenlog \
	    "$(gettext 'Completing install processing; this may take a few')"
	screenlog "$(gettext 'minutes...')"
	rm -rf "$zoneroot/oldroot"

	#
	# Remove the contents of the /dev directory created by the install.
	#
	# We don't technically need to do this, but the zone infrastructure
	# will mount $zoneroot/dev atop $rootdir/dev anyway, hiding its
	# contents so we may as well clean up after ourselves.
	#
	# The extra checks are some basic paranoia due to the potentially
	# dangerous nature of this command but are not intended to catch all
	# malicious cases
	#
	[[ "$rootdir" != "" && "$rootdir" != "/" ]] && rm -rf "$rootdir"/dev/*

	return 0
}

setup_miniroot()
{
	unset miniroot_booted

	if ! "$cwd/lx_init_zone" "$rootdir" "$logfile" mini; then
		screenlog "$mini_initfail" "$zonename"
		return 1
	fi

	if ! copy_miniroot; then
		screenlog "$mini_copyfail" "$zonename"
		return 1
	fi

	#
	# zoneadm gets upset if the zone root directory is group or world
	# readable or executable, so make sure it isn't before proceeding.
	#
	chmod 0700 "$zoneroot"

	screenlog "$(gettext 'Booting zone miniroot...')"

	if ! zoneadm -z "$zonename" boot -f; then
		screenlog "$mini_bootfail" "$zonename"
		return 1
	fi

	miniroot_booted=1

	#
	# Now that the miniroot is booted, unset the compatible architecture
	# list that expand_rpm_names was using for the miniroot so that it will
	# get the list from rpm for the full install.
	#
	unset archs

	#
	# Mount all the filesystems needed to install the new root
	# directory.
	#
	if ! newroot_lofimnt; then
		screenlog "$mini_mntfsfail" "$zonename"

		if [[ -n $newroot_mounted ]]; then
			umount_list $newroot_mounted
			unset newroot_mounted
		fi
		return 1
	fi

	#
	# Attempt to initialize the RPM database for the new zone
	#
	if ! zlogin "$zonename" /bin/rpm --initdb --root /a; then
		screenlog "$rpm_initfail" "$zonename"
		return 1
	fi

	screenlog "$(gettext 'Miniroot zone setup complete.')"
	return 0
}

finish_install()
{
	#
	# Perform some last cleanup tasks on the newly installed zone.
	#
	# Note that the zlogin commands aren't checked for errors, as the
	# newly installed zone will still boot even if the commands fail.
	#
	typeset file

	#
	# Run ldconfig in the new root
	#
	zlogin "$zonename" /usr/sbin/chroot /a \
	    /sbin/ldconfig -f /etc/ld.so.conf

	#
	# Create the /etc/shadow and /etc/gshadow files if they don't already
	# exist
	#
	[[ -a "$rootdir/a/etc/shadow" ]] ||
	    zlogin "$zonename" /usr/sbin/chroot /a /usr/sbin/pwconv

	[[ -a "$rootdir/a/etc/gshadow" ]] ||
	    zlogin "$zonename" /usr/sbin/chroot /a /usr/sbin/grpconv

	#
	# Make sure all init.d and rc[0-6].d links are set up properly.
	#
	for file in `ls "$rootdir/a/etc/init.d"`; do
		zlogin "$zonename" /usr/sbin/chroot /a \
		    /sbin/chkconfig --del $file > /dev/null 2>&1

		zlogin "$zonename" /usr/sbin/chroot /a \
		    /sbin/chkconfig --add $file > /dev/null 2>&1
	done

	replace_miniroot

	if ! "$cwd/lx_init_zone" "$rootdir" "$logfile"; then
		screenlog "$zone_initrootfail" "$zonename"
		return 1
	fi

	return 0
}

#
# Duplicate the installed "miniroot" image in a subdirectory of the base
# directory of the zone.
#
# This is done so that a new root directory can be created that will be used
# as the root of a chrooted directory that RPM running on the zone will install
# into.
#
copy_miniroot()
{
	#
	# Create the directory $zoneroot/a if it doesn't already exist
	#
	[[ -d "$zoneroot/a" ]] ||
		{ mkdir -p "$zoneroot/a" || return 1 ; }

	screenlog \
	    "$(gettext 'Duplicating miniroot; this may take a few minutes...')"

	#
	# Duplicate the miniroot to /a, but don't copy over any /etc/rc.d or
	# lxsave_ files.
	#
	( cd "$rootdir"; find . -print | egrep -v "/etc/rc\.d|lxsave_" | \
	    cpio -pdm ../a )

	[[ -d "$rootdir/a" ]] && rm -rf "$rootdir/a" 2>/dev/null
	mv -f "$zoneroot/a" "$rootdir/a" || return 1

	return 0
}

#
# Read the first four lines of the .discinfo file from the root of the passed
# disc directory (which should either be a mounted disc or ISO file.)
#
# The first four lines of the .discinfo file will be used to set appropriate
# shell variables on success:
#
#     rd_line[0]:  Disc Set Serial Number (sets rd_serial)
#     rd_line[1]:  Distribution Release Name (sets rd_release)
#     rd_line[2]:  Distribution Architecture (sets rd_arch)
#     rd_line[3]:  Disc Number in Distribution (sets rd_discnum)
#
# Returns 0 on success, 1 on failure.
#
read_discinfo()
{
        typeset rd_file="$1/.discinfo"

	verbose "read discinfo file \"$rd_file\""

        #
        # If the .discinfo file doesn't exist or isn't readable, return 1
        #
        [[ ! -f "$rd_file" || ! -r "$rd_file" ]] && return 1

	typeset rd_line

	unset rd_arch
	unset rd_discnum
	unset rd_release
	unset rd_serial

        typeset linenum=0

	while read -r rd_line[$linenum]; do
                #
                # If .discinfo architecture isn't "i386," fail here as
		# we only support i386 distros at this time.
                #
                [[ $linenum = 2 ]] && [[ "${rd_line[2]}" != "i386" ]] &&
		    return 1

                #
                # We've successfully read the first four lines of .discinfo
		# into $rd_line, so do the appropriate shell variable munging.
                #
                if ((linenum == 3)); then
			rd_serial=${rd_line[0]}
			rd_release=${rd_line[1]}

			#
			# CentOS names their releases "final"
			#
			[[ "$rd_release" = "final" ]] &&
			    rd_release="CentOS [Disc Set $rd_serial]"

			rd_arch=${rd_line[2]}
			rd_discnum=${rd_line[3]}
			return 0
		fi

                ((linenum += 1))
        done < "$rd_file"

        #
        # The file didn't have at least four lines, so indicate the read
	# failed.
        #
        return 1
}

#
# Mount a disc as reprsented by the passed device name
#
# The disc will be mounted at $zoneroot/root/disc, either via a loopback
# mount (if vold is active) or directly (if vold is not active.)
#
# Returns 0 on success, 1 on failure, 2 if no disc was available
#
mount_removable_disc()
{
	typeset device="$1"
	typeset mount_err
	mntdir="$rootdir/disc"

	removable=0

	[[ -d $mntdir ]] || if ! mkdir -p $mntdir; then
		screenlog "$mk_mntfail" "$mntdir"
		unset mntdir
		return 1
	fi

	if [[ "$vold_present" = "1" ]]; then
		#
		# allow vold to handle disc mounting
		#
		# Have volcheck check for the appropriate disc every two
		# seconds for ten seconds.
		#
		typeset mount_timeout=10
		typeset mount_interval=2

		volcheck -i $mount_interval -t $mount_timeout \
		    "$device" > /dev/null 2>&1
		
		[[ -d "$device" ]] || return 2

		mount -F lofs -o ro "$device" "$mntdir"
		mount_err=$?
	else
		#
		# Attempt to mount the disc manually
		#
		mount -F hsfs -o ro "$device" "$mntdir" 
		mount_err=$?

		((mount_err == 33)) && return 2
	fi

	if ((mount_err != 0)); then
		screenlog "$mntfail" "$device" "$mntdir"
		unset mntdir
		return 1
	fi

	verbose "Mount of \"$device\" on \"$mntdir\" succeeded!"
	removable=1
	return 0
}

#
# Eject the disc mounted on the passed directory name
#
# Returns 0 on success, 1 on failure.
#
eject_removable_disc()
{
	[[ "$removable" != "1" ]] && return 1

	typeset mount_dir="$1"
	
	get_mountdev "$mount_dir" || return 1

	umount "$mount_dir" > /dev/null 2>&1 && unset mntdir
	eject -p "$mount_dev" || return 1

	return 0
}

#
# Get a particular disc of a multi-disc set.
#
# This basically works by doing the following:
#
#     1) Mount the disc
#     2) Read the disc's .discinfo file to see which disc it is
#     3) If it's not the desired disc, eject it and ask the user to insert the
#        disc we wanted.
#
# Returns 0 on success, 1 on failure.
#
get_discnum()
{
	typeset mntdev="$1"
	typeset discnum="$2"
	typeset enter
	typeset mount_err

	while :; do
		while :; do
			mount_removable_disc "$mntdev"
			mount_err=$?

			if ((mount_err == 2)); then
				screenlog "$insert_discmsg" $discnum
				screenlog "$(gettext '<ENTER>')"
				read enter && continue
				return 1
			fi

			((mount_err == 0)) && break;

			return 1
		done

		#
		# Make sure that the mounted disc is disc $discnum.
		#
		# If it is, return to the caller, otherwise eject the
		# disc and try again. 
		#
		read_discinfo "$mntdir"

		verbose "\nRemovable Disc \"$1\": Serial \"$rd_serial\""
		verbose "  Release \"$rd_release\" Disc #$rd_discnum\n"

		[[ "$rd_discnum" = "$discnum" ]] && return 0

		screenlog "$wrong_disk" "$rd_discnum" "$discnum"
		eject_removable_disc "$mntdir" || return 1

		screenlog "$insert_discmsg" $discnum
		screenlog "$(gettext '<ENTER>')"
		read enter || return 1
	done
}

#
# Find out which distro the mounted disc belongs to
#
# Do this by cycling through the distro directory and reading each distro
# file in turn looking for:
#
#     1) The number of discs in a distribution
#     2) The serial number of the distribution
#     3) The name of the distribution
#
# Based on this, we can determine based on the ISO files available which
# distributions, if any, we have a complete set of files to support.
#
# The function returns the supported isos in the array "iso_names."
#
get_disc_distro()
{
	typeset distro
	typeset distro_files="$(echo $distro_dir/*.distro)"

	unset distro_ndiscs
	unset distro_file
	unset release
	
	[[ "$distro_files" = "$distro_dir/*.distro" ]] && return 1

	for distro in $distro_files; do
		[[ ! -f "$distro" ]] && continue
		
		verbose "Checking for disc distro \"$distro\"..."

		. "$distro" > /dev/null

		[[ "$rd_serial" != "$distro_serial" ]] && continue

		distro_file="$distro"
		distro_ndiscs="$rd_ndiscs"
		release="$rd_release"
		return 0
	done

	return 1
}

#
# Install a zone from discs
#
# Depends on the following variables:
#
#     $distro_ndiscs: Number of discs needed to fully install the distribution
#
# returns 0 on success, 1 on failure
#
install_from_discs()
{
	typeset status=0
	typeset discnum=1
	typeset mountdev="$1"
	typeset discorder
	typeset retval

	#
	# Ask for the first disc.
	#
	# We don't know which distro this may be yet, so we can't ask for
	# the first disc in the install order, so we'll just have to ask for
	# disc 1.
	#
	if ! get_discnum "$mountdev" "$discnum"; then
		screenlog "$mini_discfail" "$zonename" "1"
		return 1
	fi

	if ! get_disc_distro "$mntdir"; then
		screenlog \
		    "$(gettext 'Unable to find a supported Linux release on')"
		screenlog "$(gettext 'the media in the removable media drive.')"
		echo
		umount "$mntdir" > /dev/null 2>&1
		return 1
	fi

	. "$distro_file" > /dev/null

	check_mbfree $zoneroot $distro_mb_required || return 1

	build_rpm_list $install_packages

	echo
	screenlog "$install_ndiscs" "$distro_ndiscs"
	echo "\"$rd_release\"\n"

	#
	# Calculate the proper order for the install discs.
	#
	# distro_discorder is an array that indicates each disc's place
	# in the overall installation process.  An array of [4 1 2 3]
	# means that "Disk 1" is the 4th disk to be installed, "Disk
	# 2" is the 1st disk to be installed, and so on.
	#
	# Here we are converting that array into one that lists the
	# CDs in the order in which they should be installed, such that a
	# distro_discorder array of [4 1 2 3] would be converted into
	# a discorder array of [2 3 4 1].
	#
	while ((discnum <= distro_ndiscs)); do
		discorder[${distro_discorder[$discnum - 1]}]=$discnum
		((discnum += 1))
	done

	#
	# If the disc that was read above isn't the first disc in the install
	# order, eject it and ask for the appropriate disc.
	#
	if [[ "${discorder[1]}" != "$rd_discnum" ]]; then
		eject_removable_disc "$mntdir"
		if ! get_discnum "$mountdev" "${discorder[1]}"; then
			screenlog "$mini_discfail" "$zonename" "${discorder[1]}"
			return 1
		fi
	fi

	zone_mounted="$mntdir"

	log "Installing zone miniroot."
	screenlog "$(gettext 'Installing zone miniroot.')"

	discnum=1
	while ((discnum <= distro_ndiscs)); do
		expand_rpm_names "$mntdir" "$distro_rpmdir" \
		    $distro_miniroot_rpms

		retval=0

		if [[ -n $rpms_found ]]; then
			verbose "Installing miniroot from disc" \
			    "${discorder[$discnum]}..."

			if ! install_miniroot "$mntdir" "$distro_rpmdir" \
			    "${rpms_found[@]}"; then
				screenlog "$mini_discfail" "$zonename" \
				    "$rd_discnum"
				return 1
			fi
		fi

		#
		# If this is the first disc in the install order and we're
		# done installing the miniroot, just exit the loop without
		# ejecting the disk as we'll need it again to start the actual
		# install.
		#
		if [[ "$discnum" = "1" && -z $rpms_left ]]; then
			umount "$mntdir"
			unset zone_mounted
			break
		fi

		eject_removable_disc "$mntdir"
		unset zone_mounted

		[[ -z $rpms_left ]] && break

		distro_miniroot_rpms="${rpms_left[@]}"
		((discnum += 1))

		if ! get_discnum "$mountdev" "${discorder[$discnum]}"; then
			screenlog "$mini_discfail" "$zonename" \
			    "${discorder[$discnum]}"
			return 1
		fi

		zone_mounted="$mntdir"
	done

	if [[ -n $rpms_left ]]; then
		log ""
		log "Unable to locate some packages on install media:\n" \
		    "  ${rpms_left[@]}"
		log ""
		screenlog "$mini_instfail" "$zonename"
		return 1
	fi

	if ! setup_miniroot; then
		screenlog "$mini_setfail" "$zonename"
		return 1
	fi

	discnum=1
	while ((discnum <= distro_ndiscs)); do
		#
		# If the disc needed in the install order isn't the one in
		# the drive, eject it and ask for the correct one.
		#
		if [[ "${discorder[$discnum]}" != "$rd_discnum" ]]; then
			eject_removable_disc "$mntdir"
			if ! get_discnum "$mountdev" \
			    "${discorder[$discnum]}"; then
				screenlog "$mini_discfail" "$zonename" \
				    "${discorder[$discnum]}"
				return 1
			fi
		fi

		zone_mounted="$mntdir"

		expand_rpm_names "$rootdir/disc" "$distro_rpmdir" $distro_rpms

		retval=0

		if [[ -n $rpms_found ]]; then
			log ""
			echo
			screenlog "$install_discmsg" "$zonename" \
			    "$rd_discnum"

			if ! install_zone "$mntdir" "$distro_rpmdir" \
			    ${rpms_found[@]}; then
				screenlog "$zone_discfail" "$zonename" \
				    "$rd_discnum"
				retval=1
			fi
		fi

		eject_removable_disc "$zone_mounted"
		unset zone_mounted

		#
		# Return non-zero now if the install_zone above failed.
		#
		[[ $retval -ne 0 ]] && return $retval

		#
		# No more RPMs means we're done!
		#
		[[ -z $rpms_left ]] && break

		distro_rpms="${rpms_left[@]}"
		((discnum += 1))
	done

	if [[ -n $rpms_left ]]; then
		log ""
		log "Unable to locate some packages on install media:\n" \
		    "  ${rpms_left[@]}"
		log ""
		screenlog "$install_zonefail" "$zonename"
		return 1
	fi

	finish_install
	return $?
}

#
# Find out which distros we have ISO files to support
#
# Do this by cycling through the distro directory and reading each distro
# file in turn looking for:
#
#     1) The number of discs in a distribution
#     2) The serial number of the distribution
#     3) The name of the distribution
#
# Based on this, we can determine based on the ISO files available which
# distributions, if any, we have a complete set of files to support.
#
# The function returns the supported isos in the array "iso_names."
#
get_iso_distros()
{
	typeset index
	typeset iso_names
	typeset iso_release
	typeset serial

	typeset distro_files="$(echo $distro_dir/*.distro)"

	ndistros=0

	unset iso_set
	unset distro_file
	unset distro_ndiscs
	unset release

	[[ "$distro_files" = "$distro_dir/*.distro" ]] && return

	set -A iso_files "$@"

	for distro in $distro_files; do
		[[ ! -f $distro ]] && continue

		. "$distro" > /dev/null

		index=0
		unset iso_names
		verbose "Checking for distro \"$distro\"..."
		
		for iso in "${iso_files[@]}"; do
			[[ -z "$iso" ]] && continue

			verbose "Checking iso file mounted at \"$iso\"..."

			if [[ ! -d "$iso" || ! -r "$iso" ]]; then
				unset iso_files[$index]
				continue
			fi

			read_discinfo "$iso" || continue

			verbose "  ISO \"$iso\": Serial \"$rd_serial\""
			verbose "    Release \"$rd_release\" Disc $rd_discnum"

			if [[ -z "$serial" ]]; then
				[[ "$rd_serial" != "$distro_serial" ]] &&
				    continue

				discnum=${distro_discorder[$rd_discnum - 1]}
				verbose "Added ISO \"$iso\" as disc $discnum"
				iso_names[$discnum]="$iso"
				iso_release="$rd_release"
				serial="$rd_serial"
				unset iso_files[$index]
				((index += 1))
			else
				[[ "$rd_serial" != "$serial" ]] && continue

				discnum=${distro_discorder[$rd_discnum - 1]}
				verbose "Added ISO \"$iso\" as disc $discnum"
				iso_names[$discnum]="$iso"
				unset iso_files[$index]
				((index += 1))
			fi
		done

		[[ ${#iso_names[@]} -ne $distro_ndiscs ]] && continue

		distro_file[$ndistros]="$distro"
		distro_ndiscs[$ndistros]="$rd_ndiscs"
		iso_set[$ndistros]="${iso_names[@]}"
		release[$ndistros]="$iso_release"

		((ndistros += 1))
		((${#iso_files[@]} == 0)) && break
	done
}

#
# Do a lofi add for the passed filename and set lofi_dev to the lofi
# device name (e.g. "/dev/lofi/1".)
#
# If the passed filename already has a lofi device name, simply set lofi_dir
# to the existing device name.
#
# Returns 0 on success, 1 on failure.
#
lofi_add()
{
	typeset filename="$1"

	lofi_dev=$(lofiadm "$filename" 2>/dev/null) && return 0
	lofi_dev=$(lofiadm -a "$filename" 2>/dev/null) && return 0
	return 1
}

#
# Delete the lofi device name passed in.
#
# Returns 0 on success, 1 on failure.
#
lofi_del()
{
	typeset lofi_device="$1"

	lofiadm -d "$lofi_device" 2>/dev/null
	return $?
}

#
# Mount the lofi device name passed in.
#
# Set the variable mntdir to the directory on which the lofi device is
# mounted.
#
# Returns 0 on success, 1 on failure.
#
lofi_mount()
{
	typeset created=0
	typeset lofidev="$1"
	typeset mntroot="$2"

	#
	# Check to see if the lofi device is already mounted and return
	# the existing mount point if it is.
	#
	get_mountdir "$lofidev" && { mntdir="$mount_dir" ; return 0 ; }

	mntdir="$mntroot/iso.`/usr/bin/basename $1`"
	if [[ ! -d  "$mntdir" ]]; then
		mkdir -p "$mntdir" || return 1
		created=1
	fi

	verbose "Attempting mount of device \"$lofidev\""
	verbose "     on directory \"$mntdir\"... \c"

	if ! mount -F hsfs -o ro "$lofidev" "$mntdir" 2>/dev/null; then
		verbose "FAILED."
		((created == 1)) && rmdir -ps "$mntdir"
		return 1
	fi

	verbose "succeeded."
	return 0
}

#
# Unmount the lofi device name passed in, and remove the device mount point
# after unmounting the device.
#
# Returns 0 on success, 1 on failure.
#
lofi_umount()
{
	typeset mntdev="$1"

	#
	# If the directory name passed wasn't mounted to begin with,
	# just return success.
	#
	get_mountdir "$mntdev" || return 0

	verbose "Unmounting device \"$mntdev\"... \c"

        if ! umount "$mntdev" >/dev/null 2>&1 ; then
		verbose "FAILED."
		return 1
	fi

	verbose "succeeded."
	return 0
}

#
# Install a zone from mounted ISO files
#
# Argument: Array index of distribution to install
#
# Depends on the following variables:
#
#     $iso_set[arg]:  List of ISOs required to fully install the
#		      distribution
#
install_from_isos()
{
	typeset distro=$1
	typeset isonum=1

	set ${iso_set[$distro]}		# set passed args array

	log "Installing zone miniroot."
	screenlog "$(gettext 'Installing zone miniroot.')"

	while ((isonum <= ${distro_ndiscs[$distro]})); do
		verbose "Installing miniroot from ISO image $isonum (of" \
		    "${distro_ndiscs[$distro]})"

		ldir="${lofi_mntdir[$isonum]}"
		expand_rpm_names "$ldir" "$distro_rpmdir" $distro_miniroot_rpms

		if [[ -n $rpms_found ]]; then
			if ! install_miniroot "$ldir" "$distro_rpmdir" \
			    "${rpms_found[@]}"; then
				screenlog "$mini_isofail" "$zonename" "$ldir"
				return 1
			fi
		fi

		[[ -z $rpms_left ]] && break

		distro_miniroot_rpms="${rpms_left[@]}"
		((isonum += 1))
	done

	if [[ -n $rpms_left ]]; then
		log ""
		log "Unable to locate some packages on ISO images:\n" \
		    "  ${rpms_left[@]}"
		log ""
		screenlog "$mini_instfail" "$zonename"
		return 1
	fi

	if ! setup_miniroot; then
		screenlog "$mini_setfail" "$zonename"
		return 1
	fi

	[[ -d "$rootdir/iso" ]] || mkdir -m 0700 "$rootdir/iso"

	if [[ ! -d "$rootdir/iso" ]]; then
		screenlog "$mk_mntfail" "$rootdir/iso"
		screenlog "FAILED."
		return 1
	fi

	isonum=1
	for iso in ${iso_set[$distro]}; do
		echo
		screenlog "$install_isomsg" "$zonename" "$isonum"

		if ! mount -F lofs -o ro "$iso" "$rootdir/iso"; then
			typeset name="${iso_filename[$isonum]}"
			screenlog "iso_mntfail" "$name" "$zonename"
			return 1
		fi

		zone_mounted="$rootdir/iso"

		expand_rpm_names "$rootdir/iso" "$distro_rpmdir" $distro_rpms

		if [[ -n $rpms_found ]]; then
			log ""
			log "Installing: ${rpms_found[@]}"

			if ! install_zone "$rootdir/iso" "$distro_rpmdir" \
			    ${rpms_found[@]}; then
				screenlog "$zone_isofail" "$zonename" "$iso"
				umount "$rootdir/iso"
				return 1
			fi
		fi

		if ! umount "$rootdir/iso"; then
			screenlog "$iso_umntfail" "$name" "$zonename"
			return 1
		fi

		unset zone_mounted

		[[ -z $rpms_left ]] && break

		distro_rpms="${rpms_left[@]}"
		((isonum += 1))
	done

	if [[ -n $rpms_left ]]; then
		log ""
		log "Unable to locate some packages on ISO images:\n" \
		    "  ${rpms_left[@]}"
		log ""
		screenlog "$install_zonefail" "$zonename"
		return 1
	fi

	finish_install
	return $?
}

#
# Mount the passed list of ISOs.
#
mount_isos()
{
	typeset count=1
	typeset iso
	typeset mntroot=$1

	unset iso_filename
	unset lofi_devs
	unset lofi_mntdir

	shift
	for iso in "$@"; do
		verbose "Checking possible ISO\n  \"$iso\"..."
		if lofi_add "$iso"; then
			verbose "    added as lofi device \"$lofi_dev\""
			if lofi_mount "$lofi_dev" "$mntroot"; then
				iso_filename[$count]="$iso"
				lofi_devs[$count]="$lofi_dev"
				lofi_mntdir[$count]="$mntdir"
				((count += 1))
			else
				lofi_del "$lofi_dev"
			fi
		else
			verbose "    not a valid ISO image."
		fi
	done
}

umount_isos()
{
	typeset dev

	for dev in "$@"; do
		lofi_umount "$dev" && lofi_del "$dev"
	done
}

#
# Select a distribution to install from the arguments passed and set
# "ndsitro" to the value chosen - 1 (so it may be used as an array index.)
#
# The routine will automatically return with ndisto set to 0 if only one
# argument is passed.
#
select_distro()
{
	typeset dist
	unset ndistro

	if (($# > 1)); then
		if [[ -n $silent_mode ]]; then
			log "ERROR: multiple distrubutions present in ISO" \
				"directory but silent install"
			log "       mode specified.  Distros available:"
			for dist in "$@"; do
				log "        $dist"
			done
			return 1
		fi

		PS3="Select a distribution to install: "
		select $dist in "$@"; do
			[[ -z $distro ]] && continue
			screenlog "$install_dist" "$dist"
			ndistro=$((REPLY - 1))
		done
	fi

	#
	# Covers both the cases of when only one distro name is passed
	# to the routine as well as when an EOF is sent to the distribution
	# selection prompt.
	#
	if [[ -z $dist ]]; then
		screenlog "$install_dist" "$1"
		ndistro=0
	fi

	return 0
}

#
# Install a zone using the list of ISO files passed as arguments to this
# function.
#
# Return 0 on success, 1 on failure.
#
do_iso_install()
{
	typeset status=0

	mount_isos "/tmp/lxisos" "$@"
	if [[ -z ${lofi_mntdir[@]} ]]; then
		log "No valid ISO images available or mountable."
		screenlog \
		    "$(gettext 'No valid ISO images available or mountable.')"
		[[ -n ${lofi_devs[@]} ]] && umount_isos "${lofi_devs[@]}"
		return 1
	fi
	
	get_iso_distros "${lofi_mntdir[@]}"

	if [[ -z ${release[@]} ]]; then
		log "No valid Linux distributions found."
		screenlog "$(gettext 'No valid Linux distributions found.')"
		[[ -n ${lofi_devs[@]} ]] && umount_isos "${lofi_devs[@]}"
		return 1
	fi

	select_distro "${release[@]}" || return 1

	. ${distro_file[$ndistro]} > /dev/null

	check_mbfree $zoneroot $distro_mb_required || return 1

	build_rpm_list $install_packages

	install_from_isos $ndistro
	status=$?

	umount_isos "${lofi_devs[@]}"

	return $status
}

#
# Clean up on interrupt
#
trap_cleanup()
{
	cd "$cwd"

	screenlog "$(gettext 'Interrupt received.')"

	[[ -n $miniroot_booted ]] && zoneadm -z "$zonename" halt &&
	    unset miniroot_booted && unset newroot_mounted

	if [[ -n $zone_mounted ]]; then
		if [[ "$removable" = "1" ]]; then
			eject_removable_disc "$zone_mounted"
		else
			umount "$zone_mounted" > /dev/null 2>&1
		fi

		unset zone_mounted
	fi

	if [[ -n $newroot_mounted ]]; then
		umount_list $newroot_mounted
		unset newroot_mounted
	fi

	[[ -n $mntdir ]] && umount "$mntdir" && unset mntdir

        [[ ${#lofi_devs[@]} -ne 0 ]] && umount_isos "${lofi_devs[@]}"

	screenlog "$(gettext 'Installation aborted.')"
	exit $ZONE_SUBPROC_FATAL
}

#
# Start of main script
#
cwd=$(dirname "$0")
distro_dir="$cwd/distros"

unset distro_path
unset logfile
unset newroot_mounted
unset silent_mode
unset verbose_mode
unset zone_mounted
unset zoneroot
unset zonename

#
# Exit values used by the script, as #defined in <sys/zone.h>
#
#	ZONE_SUBPROC_OK
#	===============
#	Installation was successful
#
#	ZONE_SUBPROC_USAGE
#	==================
#	Improper arguments were passed, so print a usage message before exiting
#
#	ZONE_SUBPROC_NOTCOMPLETE
#	========================
#	Installation did not complete, but another installation attempt can be
#	made without an uninstall
#
#	ZONE_SUBPROC_FATAL
#	==================
#	Installation failed and an uninstall will be required before another
#	install can be attempted
#
ZONE_SUBPROC_OK=0
ZONE_SUBPROC_USAGE=253
ZONE_SUBPROC_NOTCOMPLETE=254
ZONE_SUBPROC_FATAL=255

#
# Process and set up various global option variables:
#
#    distro_path - Path containing files that make up the distribution
#                  (e.g. a directory containing ISO files or a disc device)
#    logfile     - Name (if any) of the install log file
#    zoneroot    - Root directory for the zone to install
#    zonename    - Name of the zone to install
#
while getopts 'svxd:l:r:z:' opt; do
	case $opt in
		s) silent_mode=1; unset verbose_mode;;
		v) verbose_mode=1; unset silent_mode;;
		x) set -x;;
		d) distro_path="$OPTARG";;
		l) logfile="$OPTARG";;
		r) zoneroot="$OPTARG";;
		z) zonename="$OPTARG";;
	esac
done
shift OPTIND-1

distro_path=${distro_path:=/cdrom/cdrom0}

install_packages="$@"

[[ -n $silent_mode ]] && exec 1>/dev/null

if [[ -z $zonename ]]; then
	screenlog \
	    "$(gettext 'ERROR:  Cannot install - no zone name was specified')"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

if [[ -z $zoneroot ]]; then
	screenlog \
	    "$(gettext 'ERROR:  Cannot install - no zone root directory was')"
	screenlog "$(gettext 'specified')"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

#
# Make sure the specified zone root directory exists
#
[[ -d "$zoneroot" ]] || mkdir -m 0700 -p "$zoneroot"

if [[ ! -d "$zoneroot" ]]; then
	screenlog "$zone_rootfail" "$zoneroot"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

rootdir="$zoneroot/root"

#
# Make sure the specified zone root subdirectory exists
#
[[ -d "$rootdir" ]] || mkdir -p "$rootdir"

if [[ ! -d "$rootdir" ]]; then
	screenlog "$zone_rootsub" "$rootdir"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

#
# Redirect stderr to the log file if it is specified and is writable
#
if [[ -n $logfile ]]; then
	if ! echo "\nInstallation started `date`" >> "$logfile" \
	    2>/dev/null; then
		screenlog "$log_wrfail" "$logfile"
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi

	exec 2>>"$logfile"
	log "Installing from path \"$distro_path\""
else
	[[ -n $silent_mode ]] && exec 2>/dev/null
fi

distro_path=${distro_path:=$default_distro_path}

#
# From this point on, call trap_cleanup() on interrupt (^C)
#
trap trap_cleanup INT

verbose "Installing zone \"$zonename\" at root \"$zoneroot\""

#
# If the distribution path starts with "/cdrom/" assume the install will be
# done from discs, otherwise assume the path is a directory containing ISO
# images.
#
if [[ "$distro_path" = /cdrom/* || "$distro_path" = /dev/dsk/* ]]; then
	if [[ -n $silent_mode ]]; then
		screenlog "$(gettext \
		    'ERROR: Cannot install from discs in silent mode.')"
		echo
		return 1
	fi

	vold_present=0

	pgrep vold > /dev/null 2>&1 && vold_present=1

	if [[ $vold_present -eq 1 && ! -d /cdrom ]]; then
		screenlog "$(gettext 'ERROR: This system does not contain a')"
		screenlog "$(gettext 'removable disc device and no ISO source')"
		screenlog "$(gettext 'directory was specified.')"
		echo
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi

	log "Installing zone \"$zonename\" at root \"$zoneroot\""
	verbose "  Attempting disc-based install via path:"
	verbose "    \"$distro_path\""
	install_from_discs $distro_path
else
	typeset dir_start

	dir_start=$(dirname "$distro_path" | cut -c 1)

	[[ "$dir_start" != "/" ]] && distro_path="`pwd`/$distro_path"

	if [[ ! -d "$distro_path" ]]; then
		screenlog "$no_distropath" "$distro_path"
		echo
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi

	log "Installing zone \"$zonename\" at root \"$zoneroot\""
	verbose "  Attempting ISO-based install from directory:"
	verbose "    \"$distro_path\""

	iso_files=$(find $distro_path -type f -print)
	do_iso_install $iso_files
fi

if [[ $? -ne 0 ]]; then
	cd "$cwd"

	[[ -n $miniroot_booted ]] && zoneadm -z "$zonename" halt &&
	    unset miniroot_booted && unset newroot_mounted

	if [[ -n $zone_mounted ]]; then
		if [[ "$removable" = "1" ]]; then
			eject_removable_disc "$zone_mounted"
		else
			umount "$zone_mounted" > /dev/null 2>&1
		fi

		unset zone_mounted
	fi

	if [[ -n $newroot_mounted ]]; then
		umount_list $newroot_mounted
		unset newroot_mounted
	fi

	log "Initial installation of zone \"$zonename\" at root \"$zoneroot\"" \
	    "FAILED."

	screenlog "$(gettext 'Cleaning up after failed install.')"

	#
	# The extra checks are some basic paranoia due to the potentially
	# dangerous nature of these commands but are not intended to catch all
	# malicious cases.
	#
	[[ -d "$zoneroot/a" ]] && rm -rf "$zoneroot/a"

	screenlog "$initinstall_zonefail" "$zonename"
	screenlog "$install_abort" "`date`"

	exit $ZONE_SUBPROC_FATAL
fi

log ""
screenlog "$install_done" "$zonename" "`date`"

exit $ZONE_SUBPROC_OK
