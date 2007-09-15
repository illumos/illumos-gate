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

# Restrict executables to /bin, /usr/bin and /usr/sbin
PATH=/bin:/usr/bin:/usr/sbin
export PATH


# Setup i18n output
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

# Log passed arguments to file descriptor 2
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

# Print and log provided text if the shell variable "verbose_mode" is set
verbose()
{
	[[ -n $verbose_mode ]] && echo "$@"
	[[ -n $logfile ]] && [[ -n $verbose_mode ]] && echo "$@" >&2
}

#
# Print to the screen if the shell variable "verbose_mode" is set, but always
# send the output to the log.
#
verboselog()
{
	[[ -n $verbose_mode ]] && echo "$@"
	[[ -n $logfile ]] && echo "$@" >&2
}

bad_rpmdir=$(gettext "'%s' is not a valid RPM directory!")

mb_req=$(gettext "(%s MB required, %s MB available)")
no_space=$(gettext "Not enough free space available in '%s'")

inst_clust=$(gettext "Installing cluster '%s'")
unknown_clust=$(gettext "ERROR: Unknown cluster name: '%s'")

unknown_media=$(gettext "Unknown or unreadable media loaded in %s")

eject_fail=$(gettext "Attempt to eject '%s' failed.")

lofi_failed=$(gettext "Attempt to add '%s' as lofi device FAILED.")
lofs_failed=$(gettext "Attempt to lofs mount '%s' on '%s' FAILED.")

media_spec=$(gettext "the provided media (%s)")

distro_mediafail=\
$(gettext "Attempt to determine Linux distribution from\n  %s FAILED.")

mini_bootfail=$(gettext "Attempt to boot miniroot for zone '%s' FAILED.")
mini_copyfail=$(gettext "Attempt to copy miniroot for zone '%s' FAILED.")
mini_initfail=$(gettext "Attempt to initialize miniroot for zone '%s' FAILED.")
mini_instfail=$(gettext "Attempt to install RPM '%s' to miniroot FAILED.")
mini_mediafail=$(gettext "Install of zone '%s' miniroot from\n  %s FAILED.")
mini_setfail=$(gettext "Attempt to setup miniroot for zone '%s' FAILED.")

mini_mntfsfail=\
$(gettext "Attempt to mount miniroot filesystems for zone '%s' FAILED.")

rpm_initfail=\
$(gettext "Attempt to initialize RPM database for zone '%s' FAILED.")

symlink_failed=$(gettext "Attempt to symbolically link '%s' to '%s' FAILED.")

discinfo_nofile=$(gettext "ERROR: Discinfo file '%s' not found!")
discinfo_notreadable=$(gettext "ERROR: Discinfo file '%s': not readable!")
discinfo_wrongarch=\
$(gettext "ERROR: '%s': disc architecture is '%s'; install requires 'i386'!")

wrong_serial=$(gettext "Incorrect serial number found on provided %s.")
wrong_ser_expect=$(gettext "  (found #%s, expected #%s)")

wrong_cd=$(gettext "Incorrect CD inserted (found %s, wanted %s)")

zone_initrootfail=\
$(gettext "Attempt to initialize root filesystem for zone '%s' FAILED.")

zone_haltfail=$(gettext "Unable to halt zone '%s'!")
zone_instfail=$(gettext "Install of zone '%s' from '%s' FAILED '%s'.")
zone_mediafail=$(gettext "Install of zone '%s' from\n  %s FAILED.")

zone_rootfail=\
$(gettext "ERROR: The specified zone root directory '%s' could not be created.")
zone_rootsub=\
$(gettext "ERROR: The specified zone root subdirectory '%s' does not exist.")

mk_mntfail=$(gettext "Could not create the mount directory '%s'")
mountfail=$(gettext "Mount of '%s' on '%s' FAILED.")

insert_discmsg=\
$(gettext "Please insert %s, or a\n  %s DVD in the removable media")

mount_proper_iso1=$(gettext "Please mount the ISO for %s or a")
mount_proper_iso2=$(gettext "%s DVD on device '%s'")

silent_nodisc=$(gettext "ERROR: Cannot install from CDs in silent mode.")
silent_nolofi=\
$(gettext "ERROR: Cannot install from lofi-based CD ISOs in silent mode.")

install_msg=$(gettext "Installing zone '%s' from\n  %s.")
install_ndiscs=\
$(gettext "You will need CDs 1 - %s (or the equivalent DVD) to")
install_nisos=\
$(gettext "You will need ISO images representing CDs 1 - %s (or the equivalent")

locate_npkgs=$(gettext "Attempting to locate %s packages...")

install_one_rpm=$(gettext "Installing 1 %spackage.")
install_nrpms_few=\
$(gettext "Installing %s %spackages; this may take a few minutes...")
install_nrpms_several=\
$(gettext "Installing %s %spackages; this may take several minutes...")

install_longwait=\
$(gettext "NOTE: There may be a long delay before you see further output.")

install_defmkfail=$(gettext "Could not create the temporary directory '%s'")
install_defcpfail=$(gettext "Could not make a local copy of deferred RPM '%s'")
install_dist=$(gettext "Installing distribution '%s'...")
install_zonefail=$(gettext "Attempt to install zone '%s' FAILED.")

no_distropath=$(gettext "ERROR: Distribution path '%s' doesn't exist.")

install_done=$(gettext "Installation of %s to zone\n  '%s' completed %s.")
install_failed=$(gettext "Installation of %s to zone\n  '%s' FAILED %s.")

eject_final_msg=\
$(gettext "Would you like the system to eject the %sinstall %s when")
eject_final_prompt=$(gettext "installation of '%s' is complete? (%s)")
eject_final_status=$(gettext "The %sinstall %s %s be ejected.")

#
# Get the device underlying a specified mounted file system and return it in
# the shell variable "mount_dev"
#
# Returns 0 on success, 1 on failure.
#
get_mountdev()
{
	typeset mount_dir="$1"
	typeset device
	unset mount_dev

	#
	# Obtain information on the specified mounted device.
	#
	device=`{ df -k "$mount_dir" | egrep "^/" ; } 2>/dev/null` || return 1
	mount_dev=$(echo $device | awk -e '{print $1}' 2>/dev/null)

	[[ "`echo $mount_dev | cut -c 1`" = "/" ]] && return 0

	unset mount_dev
	return 1
}

#
# Get the directory name a specified device is mounted as and return it in
# the shell variable "mount_dir"
#
# Returns 0 on success, 1 on failre.
#
get_mountdir()
{
	typeset mount_dev="$1"
	typeset dir
	unset mount_dir

	[[ -b "$mount_dev" ]] || return 1  

	#
	# Obtain information on the specified mounted device.
	#
	dir=`{ df -k "$mount_dev" | egrep "^/" ; } 2>/dev/null` || return 1
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
	typeset mbfree=`{ LC_ALL=C df -k "$dir" | \
	    egrep -v Filesystem ; } 2>/dev/null` || return 1
	mbfree=$(echo $mbfree | awk -e '{print $4}' 2>/dev/null)

	((mbfree /= 1024))
	if ((mbfree < mb_required)); then
		screenlog "$no_space" "$zoneroot"
		screenlog "$mb_req" "$mb_required" "$mb_free"
		return 1
	fi
	return 0
}

#
# Find packages by attempting to expand passed RPM names to their full filenames
# in the passed RPM directory.
#
# Arguments:
#
#	Argument 1:  Path to mounted install media
#	Arguments [2 - n]:  RPM names to process
#
# The expanded filenames are returned in the shell array "rpm_names."
#
# For example:
#
#	find_packages /mnt/iso dev kernel tetex redhat-menus
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
find_packages()
{
	typeset found=0
	typeset left=0

	typeset rpmdir="$1/$rd_rpmdir"
	typeset curdir=${PWD:=$(pwd)}

	typeset arch
	typeset procinfo
	typeset rpmglob
	typeset rpmfile

	unset rpms_found
	unset rpms_left

	shift
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
		    archs=$(echo $procinfo | sed 's/^compatible archs : //')

		[[ -n $archs ]] &&
		    log "RPM-reported compatible architectures: $archs"
	fi

	#
	# Either the miniroot isn't booted or asking rpm for the information
	# failed for some reason, so make some reasonable assumptions.
	#
	if [[ -z $archs ]]; then
		procinfo=$(LC_ALL=C psrinfo -vp | grep family)

		#
		# Check for additional processor capabilities
		#
		if [[ "$procinfo" = *" family 6 "* ||
		    "$procinfo" = *" family 15 "* ]]; then
			if [[ "$procinfo" = *AuthenticAMD* ]]; then
				#
				# Linux gives "athlon" packages precedence
				# over "i686" packages, so duplicate that
				# here.
				#
				archs="athlon i686"
			else
				archs="i686"
			fi
		fi

		archs="$archs i586 i486 i386 noarch"

		log "Derived compatible architectures: $archs"
	fi

	verboselog "RPM source directory:\n  \"$rpmdir\"\n"

	if [[ $# -eq 1 ]]; then
		msg=$(gettext "Attempting to locate 1 package...")
		screenlog "$msg"
	else
		screenlog "$locate_npkgs" "$#"
	fi

	for rpm in "$@"; do
		#
		# Search for the appropriate RPM, using the compatible
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
			#
			# Use the filename globbing functionality of ksh's
			# echo command to search for the file we want.
			#
			# If no matching file is found, echo will simply
			# return the passed string.
			#
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
	log "\"$rpmdir\": matched $found of $# packages."
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
		msg=$(gettext "Too many install clusters specified")
		screenlog "$msg"
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
#    install_miniroot <mounted media dir> <names of RPMS to install>
#      
#
install_miniroot()
{
        typeset mediadir="$1"
	typeset rpm

	shift

	#
	# There's a quirk in our version of ksh that sometimes resets the
	# trap handler for the shell.  Since RPM operations will be the
	# longest part of any given install, make sure that an interrupt while
	# the command is running will bring the miniroot down and clean up
	# the interrupted install.
	#
	trap trap_cleanup INT

	if [[ $# -eq 1 ]]; then
		msg=$(gettext "Installing %s miniroot package...")
	else
		msg=$(gettext "Installing %s miniroot packages...")
	fi

	screenlog "\n$msg" "$#"

        for rpm in "$@"; do
		verboselog "\nInstalling \"$rpm\" to miniroot at\n" \
			"  \"$zoneroot\"..."

		rpm2cpio "$mediadir/$rd_rpmdir/$rpm" | \
		    ( cd "$rootdir" && cpio -idu ) 1>&2

		if [[ $? -ne 0 ]]; then
			screenlog "$mini_instfail" "$rpm"
			return 1
		fi
        done

	screenlog ""
	return 0
}

#
# Install the zone from the mounted disc image by feeding a list of RPMs to
# install from this image to RPM running on the zone via zlogin(1).
#
# Usage:
#    install_zone <path to mounted install media> [<names of RPMS to install>]
#
# If the caller doesn't supply a list of RPMs to install, we install any
# we previously stashed away in the deferred RPMs directory.
#
install_zone()
{
	#
	# Convert the passed install media pathname to a zone-relative path
	# by stripping $rootpath from the head of the path.
	#
	typeset zonerpmdir="${1##$rootdir}/$rd_rpmdir"

	typeset defdir="$rootdir/var/lx_install/deferred_rpms"
	typeset mounted_root="$1"
	typeset rpmopts="-i"

	typeset defer
	typeset deferred_found
	typeset install_rpms
	typeset nrpms
	typeset rpm
	typeset rpmerr

	shift

	#
	# If the caller provided a list of RPMs, determine which of them
	# should be installed now, and which should be deferred until
	# later.
	#
	if [[ $# -gt 0 ]]; then
		if [[ -n $deferred_rpms ]]; then
			[[ -d $defdir ]] || if ! mkdir -p $defdir; then
				screenlog "$install_defmkfail" "$mntdir"
				return 1
			fi

			msg=$(gettext "Checking for deferred packages...")
			screenlog "$msg"

			find_packages "$mounted_root" $deferred_rpms
			deferred_found="${rpms_found[@]}"
			numdeferred=${#rpms_found[@]}
		else
			deferred_found=""
		fi

		install_rpms="$@"
		nrpms=$#

		#
		# If this distro has any deferred RPMs, we want to simply
	 	# copy them into the zone instead of installing them.  We
		# then remove them from the list of RPMs to be installed on
		# this pass.
		#
		for rpm in $deferred_found; do
			if echo "$install_rpms" | egrep -s "$rpm"; then
				verboselog "Deferring installation of \"$rpm\""

				#
				# Remove the RPM from the install_rpms list
				# and append it to the deferred_saved array
				#
				install_rpms=$(echo "$install_rpms " |
				    sed "s/ $rpm / /g")

				# remove trailing spaces, if any
				install_rpms=${install_rpms%%+( )}

				deferred_saved[${#deferred_saved[@]}]="$rpm"

				if ! cp "$mounted_root/$rd_rpmdir/$rpm" \
				    "$defdir"; then
					screenlog "$install_defcpfail" "$rpm"
					return 1
				fi
			fi

			#
			# If we've deferred the installation of EVERYTHING,
			# simply return success
			#
			[[ -z $install_rpms ]] && return 0
		done

		[[ -n $deferred_found ]] & verbose ""
	elif [[ -z $deferred_saved ]]; then
		# There are no deferred RPMs to install, so we're done.
		return 0
	else
		# Install the RPMs listed in the deferred_saved array
		install_rpms=${deferred_saved[@]}
		nrpms=${#deferred_saved[@]}
		zonerpmdir=/var/lx_install/deferred_rpms
		defer="deferred "
	fi

	#
	# There's a quirk in our version of ksh that sometimes resets the
	# trap handler for the shell.  Since RPM operations will be the
	# longest part of any given install, make sure that an interrupt while
	# the command is running will bring the miniroot down and clean up
	# the interrupted install.
	#
	trap trap_cleanup INT

	#
	# Print a message depending on how many RPMS we have to install.
	#
	# 25 RPMS seems like a reasonable boundary between when an install may
	# take a "few" or "several" minutes; this may be tuned if needed.
	#
	screenlog ""

	if [[ $nrpms -eq 1 ]]; then
		screenlog "$install_one_rpm" "$defer"
	elif [[ $nrpms -lt 25 ]]; then
		screenlog "$install_nrpms_few" "$nrpms" "$defer"
	else
		screenlog "$install_nrpms_several" "$nrpms" "$defer"

		#
		# For installs of over 600 packages or so, it can take rpm a
		# really, REALLY long time to output anything, even when
		# running in verbose mode.
		#
		# For example, when doing an "all" install from a DVD or DVD
		# ISO, depending on the speed of the optical drive and the
		# speed of the machine's CPU(s), it may be up to TEN MINUTES or
		# MORE before rpm prints out its "Processing..." message even
		# though it is, in fact, processing the entire package list,
		# checking for dependencies (something it is unfortunately
		# entirely silent about.)
		#
		# Since the user might otherwise think the install was hung
		# when running in verbose mode, warn them that it could be
		# quite a while before they see any further output from the
		# installer.
		#
		#
		[[ $nrpms -gt 600 ]] && verbose "$install_longwait"
	fi

	log ""
	log "Installing: $install_rpms"
	log ""
	log "NOTE:  Any messages appearing below prefixed with \"warning:\""
	log "       and/or that do not cause the installer to abort the"
	log "       installation process may safely be ignored."
	log ""

	echo

	# If verbose mode is selected, run rpm in verbose mode as well.
	[[ -n $verbose_mode ]] && rpmopts="-ivh"

	#
	# LX_INSTALL must be defined when running this command in order to
	# enable switches built into various emulated system calls to allow
	# the dev package (which may not actually write to /dev) to function.
	#
	zlogin "$zonename" "( cd "$zonerpmdir" ; LX_INSTALL=1 \
	    /bin/rpm $rpmopts --force --aid --nosignature --root /a \
	    $install_rpms )"

	rpmerr=$?

	if [[ $rpmerr -ne 0 ]]; then
		log ""
		log "Zone rpm install command exited abnormally, code $rpmerr"
		log ""

		screenlog "$zone_instfail" "$zonename" "$zonerpmdir" "$rpmerr"
		return 1
	fi

	log ""
	log "$nrpms package(s) installed."

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
	mount -F lofs -r /lib "$rootdir/a/native/lib" || return 1
	newroot_mounted="$rootdir/a/native/lib"

	if ! mount -F lofs -r /usr "$rootdir/a/native/usr"; then
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
		if [[ "$dev" = "$zoneroot/root/dev/*" ]]; then
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
			typeset source=$(LC_ALL=C file -h "$dev")

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

	#
	# After the directory munging above, we've moved the new copy of the
	# logfile atop the logfile we WERE writing to, so if we don't reopen
	# the logfile here the shell will continue writing to the old logfile's
	# inode, meaning we would lose all log information from this point on.
	#
	[[ -n $logfile ]] && exec 2>>"$logfile"

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

	if ! "$cwd/lx_init_zone" "$rootdir" mini; then
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

	msg=$(gettext "Booting zone miniroot...")
	screenlog "$msg"

	if ! zoneadm -z "$zonename" boot -f; then
		screenlog "$mini_bootfail" "$zonename"
		return 1
	fi

	miniroot_booted=1

	#
	# Now that the miniroot is booted, unset the compatible architecture
	# list that find_packages was using for the miniroot so that it will
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

	msg=$(gettext "Miniroot zone setup complete.")
	screenlog "$msg"
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

	typeset defdir=$rootdir/var/lx_install/deferred_rpms

	msg=$(gettext "Completing installation; this may take a few minutes.")
	screenlog "$msg"

	if [[ -d $defdir ]]; then
		rm -f $defdir/*.rpm
		rmdir $defdir
	fi

	# Run ldconfig in the new root
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

	rmdir -ps "$media_mntdir"

	if ! "$cwd/lx_init_zone" "$rootdir"; then
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

	msg=$(gettext "Duplicating miniroot; this may take a few minutes...")
	screenlog "$msg"

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
# Read the first six lines of the  .discinfo file from the root of the passed
# disc directory (which should either be a mounted disc or ISO file.)
#
# The read lines will be used to set appropriate shell variables on success:
#
#     rd_line[0]:  Disc Set Serial Number (sets rd_serial)
#     rd_line[1]:  Distribution Release Name (sets rd_release)
#     rd_line[2]:  Distribution Architecture (sets rd_arch)
#     rd_line[3]:  Disc Number$[s] in Distribution (sets rd_cdnum)
#     rd_line[4]:  "base" directory for disc (currently unused)
#     rd_line[5]:  RPM directory for disc (sets rd_rpmdir)
#
# Returns 0 on success, 1 on failure.
#
read_discinfo()
{
        typeset rd_file="$1/.discinfo"

	unset rd_arch
	unset rd_cdnum
	unset rd_disctype
	unset rd_pers
	unset rd_release
	unset rd_rpmdir
	unset rd_serial

	#
	# If more than one argument was passed to read_discinfo, the second
	# is a flag meaning that we should NOT print a warning message if
	# we don't find a .discinfo file, as this is just a test to see if
	# a distribution ISO is already mounted on the passed mount point.
	#
	if [[ ! -f "$rd_file" ]]; then
		[[ $# -eq 1 ]] &&
		    screenlog "$discinfo_nofile" "$rd_file"
		return 1
	fi

	verbose "Attempting to read \"$rd_file\"..."

        if [[ ! -r "$rd_file" ]]; then
		screenlog "$discinfo_notreadable" "$rd_file"
		return 1
	fi

	typeset rd_line
        typeset linenum=0

	while read -r rd_line[$linenum]; do
                #
                # If .discinfo architecture isn't "i386," fail here as
		# we only support i386 distros at this time.
                #
                if [[ $linenum = 2 && "${rd_line[2]}" != "i386" ]]; then
			screenlog "$discinfo_wrongarch" "$rd_file" \
			    "${rd_line[2]}"
			return 1
		fi

                #
                # We've successfully read the first six lines of .discinfo
		# into $rd_line, so do the appropriate shell variable munging.
                #
                if ((linenum == 5)); then
			rd_serial=${rd_line[0]}
			rd_release=${rd_line[1]}

			# CentOS names their releases "final"
			[[ "$rd_release" = "final" ]] && rd_release="CentOS"

			#
			# Line four of the .discinfo file contains either a
			# single disc number for a CD or a comma delimited list
			# representing the CDs contained on a particular DVD.
			#
			rd_cdnum=${rd_line[3]}

			if [[ "$rd_cdnum" = *,* ]]; then
				rd_disctype="DVD"
			else
				rd_disctype="CD"
			fi

			rd_rpmdir=${rd_line[5]}

			#
			# If the specified RPM directory doesn't exist, this is
			# not a valid binary RPM disc (it's most likely a
			# source RPM disc), so don't add it to the list of
			# valid ISO files.
			#
			[[ ! -d "$1/$rd_rpmdir" ]] && return 1

			if [[ "$rd_cdnum" = "1" &&
			   "$rd_release" = "Red Hat"* ]]; then
				typeset rh_glob

				#
				# If this is a Red Hat release, get its
				# personality name from the name of the
				# redhat-release RPM package.
				#
				# Start by looking for the file
				# "redhat-release-*.rpm" in the directory
				# RedHat/RPMS of the ISO we're examining by
				# using ksh's "echo" command to handle
				# filename globbing.
				#
				# If no matching file is found, echo will
				# simply return the passed string.
				#
				rh_glob="$1/RedHat/RPMS/redhat-release-*.rpm"
				rd_pers="$(echo $rh_glob)"

				if [[ "$rd_pers" != "$rh_glob" ]]; then
					#
					# An appropriate file was found, so
					# extract the personality type from the
					# filename.
					#
					# For example, the presence of the file:
					#
					#   redhat-release-3WS-13.5.1.i386.rpm
					#
					# would indicate the ISO either
					# represents a "WS" personality CD or
					# a "WS" installation DVD.
					#
					# Start the extraction by deleting the
					# pathname up to the personality type.
					#
					rh_glob="*/redhat-release-[0-9]"
					rd_pers="${rd_pers##$rh_glob}"

					#
					# Now remove the trailing portion of the
					# pathname to leave only the personality
					# type, such as "WS" or "ES."
					#
					rd_pers="${rd_pers%%-*\.rpm}"
				else
					unset rd_pers
				fi
			fi

			return 0
		fi

                ((linenum += 1))
        done < "$rd_file"

        #
        # The file didn't have at least six lines, so indicate that parsing
	# failed.
        #
        return 1
}

#
# Mount install media within the zone.
#
# The media will be mounted at $zoneroot/root/media, either via a loopback
# mount (if it's a managed removable disc) or directly (if the media is an ISO
# file or if the specified filename is a block device.)
#
# Returns 0 on success, 1 on failure, 2 if no disc was available
#
mount_install_media()
{
	typeset device="$1"
	typeset mount_err

	unset removable
	unset zone_mounted

	[[ -z $mntdir ]] && return 1

	[[ -d $mntdir ]] || if ! mkdir -p $mntdir; then
		screenlog "$mk_mntfail" "$mntdir"
		unset mntdir
		return 1
	fi

	if [[ "$install_media" = "disc" && "$managed_removable" = "1" ]]; then
		#
		# The removable disc device is an automatically managed one,
		# so just wait for the device mounter to notice a disc has been
		# inserted into the drive and for the disc to appear at the
		# mount point.
		#
		typeset mount_interval=2
		typeset mount_timeout=10
		typeset mount_timer=0

		typeset nickname=$(basename $device)

		eject -q "$nickname" > /dev/null 2>&1 || return 2
		removable="$nickname"

		#
		# Double check that the device was mounted.  If it wasn't, that
		# usually means the disc in the drive isn't in a format we can
		# read or the physical disc is unreadable in some way.
		#
		# The mount_timer loop is needed because the "eject -q" above
		# may report a disc is available before the mounter associated
		# with the drive actually gets around to mounting the device,
		# so we need to give it a chance to do so.  The mount_interval
		# allows us to short-circuit the timer loop as soon as the
		# device is mounted.
		#
		while ((mount_timer < mount_timeout)); do
			[[ -d "$device" ]] && break

			sleep $mount_interval
			((mount_timer += mount_interval))
		done

		if [[ ! -d "$device" ]]; then
			screenlog "\n$unknown_media" "$device"
			return 2
		fi

		mount -F lofs -r "$device" "$mntdir"
		mount_err=$?
	else
		#
		# Attempt to mount the media manually.
		#
		# First, make sure the passed device name really IS a device.
		#
		[[ -b "$device" ]] || return 2

		#
		# Now check to see if the device is already mounted and lofi
		# mount the existing mount point into the zone if it is.
		#
		if get_mountdir "$device"; then
			mount -F lofs -r "$mount_dir" "$mntdir"
			mount_err=$?
		else
			[[ "$install_media" = "disc" ]] && removable="$device"

			# It wasn't mounted, so go ahead and try to do so.
			mount -F hsfs -r "$device" "$mntdir" 
			mount_err=$?
		fi

		# A mount_err of 33 means no suitable media was found
		((mount_err == 33)) && return 2
	fi

	if ((mount_err != 0)); then
		screenlog "$mountfail" "$device" "$mntdir"
		unset mntdir
		return 1
	fi

	zone_mounted="$mntdir"
	verbose "Mount of \"$device\" on \"$mntdir\" succeeded."
	return 0
}

# Eject the disc mounted on the passed directory name
eject_removable_disc()
{
	screenlog ""
	verbose "  (Attempting to eject '$removable'... \c"

	if [[ -n $zone_mounted ]]; then
		umount "$zone_mounted"
		unset zone_mounted
	fi

	if ! eject "$removable"; then
		verbose "failed.)\n"
		screenlog "$eject_fail" "$removable"

		msg=$(gettext "Please eject the disc manually.")
		screenlog "$msg"
	else
		verbose "done.)\n"
	fi

	unset removable
}

#
# Ask for the user to provide a disc or ISO.
#
# Returns 0 on success, 1 on failure.
#
prompt_for_media()
{
	# No prompting is allowed in silent mode.
	if [[ -n $silent_mode ]]; then
		log "$silent_err_msg"
		return 1
	fi

	if [[ "$1" != "" ]]; then
		msg="$release_name, CD $1"
	else
		typeset disc=$(gettext "disc")

		msg=$(gettext "any")
		msg="$msg $release_name $disc"
	fi

	if [[ "$install_media" = "disc" ]]; then
		screenlog "$insert_discmsg" "$msg" "$release_name"

		msg=$(gettext "drive and press <RETURN>.")
		screenlog "  $msg"

		[[ -n $removable ]] && eject_removable_disc
	else
		if [[ -n $zone_mounted ]]; then
			umount "$mntdir"
			unset zone_mounted
		fi

		#
		# This is only be printed in the case of a user
		# specifying a device name as an install medium.
		# This is handy for testing the installer or if the user
		# has ISOs stored in some strange way that somehow
		# breaks the "install from ISO" mechanism, as ISOs
		# can be manually added using lofiadm(1M) command and
		# the resulting lofi device name passed to the
		# installer.
		#
		screenlog "$mount_proper_iso1" "$msg"
		screenlog "  $mount_proper_iso2" "$release_name" "$mntdev"

		msg=$(gettext "and press <RETURN>.")
		screenlog "  $msg"
	fi

	read && return 0
	
	return 1
}

#
# Get a particular CD of a multi-disc set.
#
# This basically works by doing the following:
#
#     1) Mount the disc
#     2) Read the disc's .discinfo file to see which CD it is or represents
#     3) If it doesn't contain the desired CD, ask the user for a disc
#	 containing the CD we wanted.
#
# Returns 0 on success, 1 on failure.
#
get_cd()
{
	typeset mntdev="$1"

	typeset cdnum
	typeset discname
	typeset enter
	typeset mount_err
	typeset prompted


	if [[ $# -eq 2 ]]; then
		# Caller specified a particular CD to look for
		cdnum="$2"
		discname="$release_name, CD $cdnum"
	else
		# Caller wanted any disc
		discname="a $release_name disc"
	fi

	verboselog "\nChecking for $discname on device"
	verboselog "  \"$mntdev\"\n"

	while :; do
		# Check to see if a distro disc is already mounted
		mntdir="$media_mntdir"

		unset rd_disctype
		if ! read_discinfo "$mntdir" "test"; then
			mount_install_media "$mntdev"
			mount_err=$?

			#
			# If the mount succeeded, continue on in the main
			# script
			#
			if ((mount_err == 0)); then
				read_discinfo "$mntdir"
			elif ((mount_err == 2)); then
				# No medium was found, so prompt for one.
				prompt_for_media "$cdnum" && prompted=1 continue

				unset mntdir
				return 1
			else
				# mount failed
				unset mntdir
				return 1
			fi
		fi

		if [[ -n $distro_serial && 
		    "$rd_serial" != "$distro_serial" ]]; then
			screenlog "$wrong_serial" "$install_disctype"
			screenlog "  $wrong_ser_expect" "$rd_serial" \
			    "$distro_serial"

			#
			# If we're installing from ISOs, don't prompt the user
			# if the wrong serial number is present, as there's
			# nothing they can do about it.
			#
			[[ "$install_media" = "ISO" ]] && return 1

			prompt_for_media "$cdnum" && continue

			umount "$mntdir"
			unset zone_mountdir
			return 1
		fi

		#
		# Make sure that the mounted media is CD $cdnum.
		#
		# If it is, return to the caller, otherwise eject the
		# disc and try again. 
		#
		if [[ "$rd_disctype" = "CD" ]]; then
			verboselog "Found CD #$rd_cdnum," \
			    "Serial #$rd_serial"
			verboselog "Release Name \"$rd_release\""

			[[ -n $rd_pers ]] &&
			    verboselog "Detected RedHat Personality" \
				"\"$rd_pers\""

			verboselog ""

			# If we didn't care which CD it was, return success
			[[ "$cdnum" = "" ]] && return 0

			# Return if the CD number read is a match
			[[ "$rd_cdnum" = "$cdnum" ]] && return 0
		else
			verboselog "\nFound DVD (representing CDs" \
			    "$rd_cdnum), Serial #$rd_serial"
			verboselog "Release Name \"$rd_release\"\n"

			[[ -n $rd_pers ]] &&
			    verboselog "Detected RedHat Personality" \
				"\"$rd_pers\""

			verboselog ""

			# If we didn't care which CD it was, return success
			[[ "$cdnum" = "" ]] && return 0

			#
			# Since a DVD represents multiple CDs, make sure the
			# DVD inserted represents the CD we want.
			#
			{ echo "$rd_cdnum," | egrep -s "$cdnum," ; } &&
			    return 0
		fi

		if [[ -n $prompted ]]; then
			if [[ "$rd_disctype" = "CD" ]]; then
				screenlog "$wrong_cd" "$rd_cdnum" "$cdnum"
			else
				msg=$(gettext "Incorrect DVD inserted.")
				screenlog "$msg"

				log "(DVD represented CDs $rd_cdnum," \
				    " wanted CD $cdnum)"
			fi
		fi

		#
		# If we're installing from ISOs, don't prompt the user if the
		# wrong CD is mounted, as there's nothing they can do about it.
		#
		[[ "$install_media" = "ISO" ]] && return 1

		prompt_for_media "$cdnum" && prompted=1 && continue

		umount "$mntdir"
		unset zone_mountdir
		return 1
	done
}

#
# Find out which distro the mounted disc belongs to by comparing the
# mounted disc's serial number against those contained in the various
# distro files.
#
# When a match is found, the shell variable "distro_file" will be set to
# the name of the matching file.  Since that will have been the last file
# sourced by the shell, there's no need for the caller to do it again; the
# variable is only set in case it's of some use later.
#
# Returns 0 on success, 1 on failure.
#
get_disc_distro()
{
	typeset distro
	typeset distro_files="$(echo $distro_dir/*.distro)"

	unset distro_file
	
	[[ "$distro_files" = "$distro_dir/*.distro" ]] && return 1

	for distro in $distro_files; do
		[[ ! -f "$distro" ]] && continue
		
		verbose "Checking for disc distro \"$distro\"..."

		. "$distro" > /dev/null

		[[ "$rd_serial" != "$distro_serial" ]] && continue

		distro_file="$distro"
		release_name="$rd_release $distro_version"
		distro_ncds=${#distro_cdorder[@]}

		return 0
	done

	return 1
}

#
# Iterate through the install media to install the miniroot and full zone
#
# The install media may be physical discs, a lofi mounted ISO file, or
# iso files located in a directory specified by the user.
#
# All installations, regardless of media type, use a CD as their basic media
# unit.  DVDs or ISOs representing DVDs actually contain multiple "CDs" of
# installation packages.
#
# The variable "distro_ncds," as set elsewhere, represents the number
# of CDs required to install the distribution.  Whether the installation
# actually requires multiple physical discs or ISOs depends upon their content.
#
# Returns 0 on success, 1 on failure.
#
iterate_media()
{
	typeset cdnum=1
	typeset cds
	typeset disc_rpms
	typeset err_media
	typeset err_msg
	typeset install_type="$1"
	typeset ldevs
	typeset mountdev
	typeset rh_pers

	shift

	if [[ "$install_type" = "miniroot" ]]; then
		typeset i

		disc_rpms=$distro_miniroot_rpms
		err_msg="$mini_mediafail"

		# For miniroot installs, ask for CDs in numerical order
		cds[0]="zero_pad"

		for i in ${distro_cdorder[@]}; do
			cds[$cdnum]=$cdnum
			((cdnum += 1))
		done

		cdnum=1
	else
		disc_rpms=$distro_rpms
		err_msg="$zone_mediafail"

		#
		# For full zone installs, ask for CDs in the order RPM needs
		# to find the packages.
		#
		set -A cds "zero_pad" ${distro_cdorder[@]}
	fi

	if [[ "$install_media" = "ISO" ]]; then
		set -A ldevs "zero_pad" "$@"
	else
		mountdev="$1"
		err_media="$release_name, CD ${cds[$cdnum]} (or DVD)"
	fi

	unset rpms_left_save

	while ((cdnum <= distro_ncds)); do
		[[ -z ${cds[$cdnum]} ]] && ((cdnum += 1)) && continue

		if [[ "$install_media" = "ISO" ]]; then
			typeset isonum="${cds[$cdnum]}"

			#
			# If this routine was called with a single ISO device
			# name, it must be a DVD, so refer to that one lofi
			# device (and associated ISO pathname)
			#
			[[ $# -eq 1 ]] && isonum=1

			err_media="ISO \"${iso_pathnames[$isonum]}\""
			mountdev="${ldevs[$isonum]}"
		fi

		#
		# If the disc needed in the install order isn't the one in
		# the drive, ask for the correct one.
		#
		if ! get_cd "$mountdev" "${cds[$cdnum]}"; then
			screenlog "$err_msg" "$zonename" "$err_media"
			return 1
		fi

		# set the RedHat personality type, if applicable
		[[ -n $rd_pers && -z $rh_pers ]] && rh_pers=$rd_pers

		#
		# We now know the actual type of media being used, so
		# modify the "err_media" string accordingly.
		#
		if [[ "$install_media" = "disc" ]]; then
			if [[ "$rd_disctype" = "DVD" ]]; then
				err_media="$release_name DVD"
			else
				err_media="$release_name, CD ${cds[$cdnum]}"
			fi
		fi

		find_packages "$mntdir" $disc_rpms

		#
		# Save a copy of $rpms_left.  Other functions clobber it.
		#
		rpms_left_save="${rpms_left[@]}"

		if [[ -n $rpms_found ]]; then
			if [[ "$install_type" = "miniroot" ]]; then
				verboselog "\nInstalling miniroot from"
				verboselog "  $err_media...\n" 

				if ! install_miniroot "$mntdir" \
				    "${rpms_found[@]}"; then
					screenlog "$err_msg" "$zonename" \
						"$err_media"
					return 1
				fi
			else
				screenlog "\n$install_msg\n" "$zonename" \
				    "$err_media"

				if ! install_zone "$mntdir" \
				    ${rpms_found[@]}; then
					screenlog "$err_msg" "$zonename" \
					    "$err_media"
					return 1
				fi
			fi

			#
			# Mark installation from this CD (or ISO representing
			# this CD) as completed.
			#
			if [[ "$rd_disctype" = "CD" ]]; then
				unset cds[$cdnum]
			fi
		fi

		# A DVD install takes a single disc, so stop iterating
		[[ "$rd_disctype" = "DVD" ]] && break

		# If there are no RPMs left, we're done.
		[[ -z $rpms_left_save ]] && break

		disc_rpms="$rpms_left_save"
		((cdnum += 1))

		if [[ "$install_media" != "ISO" ]]; then
			#
			# modify the err_media variable to reflect the next
			# CD in the sequence
			#
			err_media="$release_name, CD ${cds[$cdnum]}"
		else
			# Unmount the last used ISO if appropriate
			if [[ -n $zone_mounted ]]; then
				umount "$zone_mounted"
				unset zone_mounted
			fi
		fi
	done

	if [[ -n $zone_mounted ]]; then
		umount "$zone_mounted"
		unset zone_mounted
	fi

	if [[ -n $rpms_left_save ]]; then
		#
		# Uh oh - there were RPMS we couldn't locate.  This COULD
		# indicate a failed installation, but we need to check for
		# a RedHat personality "missing" list first.
		#
		if [[ -n $rh_pers && "$rh_pers" != "AS" ]]; then
			typeset missing

			if [[ $rh_pers = "WS" ]]; then
				missing="$distro_WS_missing"
			elif [[ $rh_pers = "ES" ]]; then
				missing="$distro_ES_missing"
			fi

			#
			# If any packages left in "rpm_left_save" appear in the
			# list of packages expected to be missing from this
			# personality, remove them from the "rpm_left_save"
			# list.
			#
			if [[ -n $missing ]]; then
				typeset pkg

				for pkg in $missing
				do
					rpm_left_save=$(echo "$rpm_left_save " |
					    sed "s/$pkg //g")

					#
					# If all of the packages in
					# "rpm_left_save" appeared in this
					# personality's list of "expected
					# missing" packages, then the
					# installation completed successfully.
					#
					[[ -z ${rpm_left_save%%+( )} ]] &&
					    return 0
				done
			fi
		fi

		log "\nERROR: Unable to locate some needed packages:\n" \
		    "  ${rpms_left_save%%+( )}\n"
		screenlog "$err_msg" "$zonename"
		return 1
	fi

	return 0
}

#
# Install a zone from installation media
#
# Returns 0 on success, 1 on failure
#
install_from_media()
{
	msg=$(gettext "Installing miniroot for zone '%s'.")
	screenlog "$msg" "$zonename"

	iterate_media "miniroot" $@ || return 1

	if ! setup_miniroot; then
		screenlog "$mini_setfail" "$zonename"
		return 1
	fi

	msg=$(gettext "Performing full install for zone '%s'.")

	screenlog "\n$msg" "$zonename"

	iterate_media "full" $@ || return 1

	#
	# Attempt to install deferred RPMS, if any
	#
	if [[ -n $deferred_rpms ]]; then
		if ! install_zone ""; then
			return 1
		fi
	fi

	finish_install
	return $?
}

#
# Add an entry to the valid distro list.
#
# The passed argument is the ISO type ("CD Set" or "DVD")
#
add_to_distro_list()
{
	typeset name

	distro_file[${#distro_file[@]}]="$distro"

	name="$release_name"
	[[ -n $redhat_pers ]] && name="$name $redhat_pers"

	select_name[${#select_name[@]}]="$name ($1)"
	release[${#release[@]}]="$release_name"
	iso_set[${#iso_set[@]}]="${iso_names[@]}"
	verboselog "Distro \"$name\" ($1) found."
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
# The function returns the supported isos in the array "iso_set."
#
validate_iso_distros()
{
	typeset cd
	typeset disctype
	typeset index
	typeset iso
	typeset ncds
	typeset pers
	typeset pers_cd
	typeset pers_index
	typeset serial

	typeset distro_files="$(echo $distro_dir/*.distro)"
	typeset nisos=${#iso_filename[@]}

	unset distro_file
	unset iso_set
	unset release
	unset select_name

	if [[ "$distro_files" = "$distro_dir/*.distro" ]]; then
		msg=$(gettext "Unable to find any distro files!")
		screenlog "$msg"
		return
	fi

	for distro in $distro_files; do
		#
		# We're done if we've already processed all available ISO files
		# or if there were none in the first place.
		#
		((${#iso_filename[@]} == 0)) && break

		[[ ! -f $distro ]] && continue

		. "$distro" > /dev/null
		ncds=${#distro_cdorder[@]}

		unset iso_names
		unset pers
		unset pers_cd

		verbose "\nChecking ISOs against distro file \"$distro\"..."

		index=0

		while ((index < nisos)); do
			#
			# If the filename has been nulled out, it's already
			# been found as part of a distro, so continue to the
			# next one.
			#
			if [[ -z ${iso_filename[$index]} ]]; then
				((index += 1))
				continue
			fi

			iso="${iso_filename[$index]}"
			serial="${iso_serial[$index]}"
			release_name="${iso_release[$index]}"
			redhat_pers="${iso_pers[$index]}"

			verbose "  ISO \"$iso\":"

			#
			# If the serial number doesn't match that for
			# this distro, check other ISOs
			#
			if [[ "$serial" != "$distro_serial" ]]; then
				((index += 1))
				continue
			fi

			verbose "    Serial #$serial"
			verbose "    Release Name \"$release_name\""

			[[ -n ${iso_pers[$index]} ]] &&
			    verbose "    RedHat Personality \"$redhat_pers\""

			if [[ "${iso_disctype[$index]}" = "CD" ]]; then
				disctype="CD #"
				cd="${iso_cdnum[$index]}"
			else
				disctype="DVD, representing CDs #"
				cd=0
			fi

			verbose "    ${disctype}${iso_cdnum[$index]}\n"

			#
			# Once we've matched a particular distro, don't check
			# this ISO to see if it's part of any other.
			#
			unset iso_filename[$index]

			iso_names[$cd]="$iso"

			#
			# A DVD-based distro consists of one and ONLY one disc,
			# so process it now.
			#
			if [[ "${iso_disctype[$index]}" = "DVD" ]]; then
				typeset dvd_discs=",${iso_cdnum[$index]}"

				cd=1 
				while ((cd <= ncds)); do
					dvd_discs=$(echo "$dvd_discs" |
					    sed "s/,$cd//")
					((cd += 1))
				done

				#
				# If no CDs are left in $dvd_discs, the DVD
				# was a complete distribution, so add it to
				# the valid distro list.
				#
				if [[ -z $dvd_discs ]]; then
					add_to_distro_list "DVD"
					unset iso_names[$cd]
				fi
			elif [[ -n ${iso_pers[$index]} ]]; then
				#
				# If this is a RedHat personality CD, save off
				# some extra information about it so we can
				# discern between mutiple personality discs
				# later, if needed.
				#
				pers[${#pers[@]}]=${iso_pers[$index]}
				pers_cd[${#pers_cd[@]}]="$iso"
			fi

			((index += 1))
		done

		#
		# Check to see if we have ISOs representing a full CD set.
		# If we don't, don't mark this as an available distro.
		#
		(( ${#iso_names[@]} != $ncds )) && continue

		relase_name="$release_name $distro_version"
		
		if [[ -z ${pers[@]} ]]; then
			#
			# If there were no personality discs, just add this
			# ISO set to the distro list.
			#
			unset redhat_pers
			add_to_distro_list "CD Set"
		else
			#
			# If a valid CD-based distro was found and there are
			# RedHat personality discs for that distro present,
			# create entries for each personality in the available
			# distro list.
			#
			pers_index=0

			while ((pers_index < ${#pers[@]})); do
				redhat_pers=${pers[$pers_index]}

				if [[ -n ${pers_cd[$pers_index]} ]]; then
					#
					# RedHat personality discs are always
					# disc 1 of a CD set, so if we found a
					# valid personality disc for this set,
					# set the disc 1 entry for this distro
					# to the ISO for the proper personality
					# disc.
					#
					iso_names[1]="${pers_cd[$pers_index]}"
					add_to_distro_list "CD Set"
				fi

				((pers_index += 1))
			done
		fi
	done
}

#
# Do a lofi add for the passed filename and set lofi_dev to the lofi
# device name lofiadm created for it (e.g. "/dev/lofi/1".)
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
	lofi_dev=$(lofiadm -a "$filename") && return 0

	screenlog "$lofi_failed" "$filename"
	return 1
}

#
# Delete the lofi device name passed in.
#
# Returns 0 on success, 1 on failure.
#
lofi_del()
{
	typeset dev="$1"

	[[ "$dev" != /dev/lofi/* ]] && return 1

	if lofiadm -d "$dev" 2>/dev/null; then
		[[ -n $lofi_dev ]] && unset lofi_dev
		return 0
	fi

	return 1 
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
	typeset lofidev="$1"
	typeset mntpoint="$2"

	#
	# Check to see if the lofi device is already mounted and return
	# the existing mount point if it is.
	#
	get_mountdir "$lofidev" && { mntdir="$mount_dir" ; return 0 ; }

	unset mntdir
	if [[ ! -d  "$mntpoint" ]]; then
		if ! mkdir -p "$mntpoint"; then
			log "Could not create mountpoint \"$mntpoint\"!\n"
			return 1
		fi
		lofi_created="$mntpoint"
	fi

	verbose "Attempting mount of device \"$lofidev\""
	verbose "  on directory \"$mntpoint\"... \c"

	if ! mount -F hsfs -r "$lofidev" "$mntpoint" 2>/dev/null; then
		verbose "FAILED."
		[[ -n $lofi_created ]] && rmdir -ps "$lofi_created" &&
		    unset lofi_created
		return 1
	fi

	mntdir="$mntpoint"
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

        if ! umount "$mntdev" ; then
		verbose "FAILED."
		return 1
	fi

	verbose "succeeded."
	return 0
}

# Scan the passed list of ISOs.
scan_isos()
{
	typeset iso
	typeset index=0

	unset iso_serial
	unset iso_release
	unset iso_cdnum
	unset iso_disctype
	unset iso_filename
	unset iso_pers

	for iso in "$@"; do
		verbose "Checking possible ISO\n  \"$iso\"..."

		if lofi_add "$iso"; then
			verbose "  added as lofi device \"$lofi_dev\""
			if lofi_mount "$lofi_dev" "/tmp/lxiso"; then
				if read_discinfo "$mntdir"; then
					iso_release[$index]="$rd_release"
					iso_serial[$index]="$rd_serial"
					iso_cdnum[$index]="$rd_cdnum"
					iso_disctype[$index]="$rd_disctype"

					[[ -n $rd_pers ]] &&
					    iso_pers[$index]="$rd_pers"

					iso_filename[$index]="$iso"
					((index += 1))
				fi
				lofi_umount "$lofi_dev"
			else
				verbose "  not a usable ISO image."
				log "Unable to mount \"$lofi_dev\" (\"$iso\")"
			fi

			lofi_del "$lofi_dev"
		else
			verbose "  not a valid ISO image."
		fi
	done
}

#
# Prompt the user with the first argument, then make a menu selection
# from the balance.
#
# This is effectively similar to the ksh "select" function, except it
# outputs to stdout.
#
# Shell variables set:
#    choice    - set to the menu number selected
#    selection - set to the menu text selected
#
pick_one()
{
	typeset menu_items
	typeset menu_index
	typeset reply

	typeset prompt="$1"
	shift

	unset choice

	set -A menu_items "$@"

	until [[ -n $choice ]]; do
		menu_index=1
		
		echo "\n$prompt\n"

		for f in "${menu_items[@]}"; do
			echo "$menu_index) $f"
			((menu_index += 1))
		done

		echo "\n$(gettext "Please select") (1-$#): " "\c"
		read reply
		echo

		[[ -z $reply ]] && echo && continue

		#
		# Reprint menu selections if the answer was not a number in
		# range of the menu items available
		#
		[[ $reply != +([0-9]) ]] && continue
		((reply < 1)) || ((reply > $#)) && continue

		choice=$reply
		selection=${menu_items[((choice - 1))]}
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
	unset choice
	unset ndistro

	if (($# > 1)); then
		if [[ -n $silent_mode ]]; then
			typeset dist

			log "ERROR: multiple distrubutions present in ISO" \
				"directory but silent install"
			log "  mode specified.  Distros available:"
			for dist in "$@"; do
				log "    \"$dist\""
			done
			return 1
		fi

		pick_one \
		    "$(gettext "Which distro would you like to install?")" \
		    "$@"
	fi

	#
	# Covers both the cases of when only one distro name is passed
	# to the routine as well as when an EOF is sent to the distribution
	# selection prompt.
	#
	if [[ -z $choice ]]; then
		screenlog "$install_dist" "$1"
		ndistro=0
	else
		screenlog "$install_dist" "$selection"
		ndistro=$((choice - 1))
	fi

	return 0
}

#
# Install a zone from discs or manually lofi-mounted ISOs.
#
# Return 0 on success, 1 on failure
#
do_disc_install()
{
	typeset path="$1"

	typeset eject_final="N"
	typeset install_status

	#
	# Get a disc, it doesn't matter which one.
	#
	# We don't know which distro this may be yet, so we can't yet
	# ask for the first disc in the install order.
	#
	if ! get_cd "$path"; then
		if [[ -z $silent_mode ]]; then
			typeset distro_disc=\
			    $(gettext "a supported Linux distribution disc")

			screenlog "\n$distro_mediafail" "$distro_disc ($path)"
		fi
		return 1
	fi

	if [[ -n $silent_mode && "$rd_disctype" = "CD" ]]; then
		log "$silent_err_msg"
		return 1
	fi

	if ! get_disc_distro "$mntdir"; then
		msg=$(gettext "Unable to find a supported Linux release on")
		screenlog "$msg"
		screenlog "  $media_spec" "$path"
		umount "$mntdir" > /dev/null 2>&1
		return 1
	fi

	check_mbfree $zoneroot $distro_mb_required || return 1
	build_rpm_list $install_packages

	echo

	if [[ "$install_media" = "disc" ]]; then
		#
		# If we're in interactive mode, ask the user if they want the
		# disc ejected when the installation is complete.
		#
		# Silent mode installs will require the user to manually run
		# eject(1).
		#
		if [[ -n $removable && -z $silent_mode ]]; then
			typeset ans
			typeset disc
			typeset status
			typeset which=""

			disc="$rd_disctype"
			[[ "$disc" = "CD" ]] && which=$(gettext "final ")

			#
			# Ask the user if they want the install disc ejected
			# when the installation is complete.  Any answer but
			# "n" or "N" is taken to mean yes, eject it.
			#
			eject_final="Y"
			status=$(gettext "WILL")

			screenlog "$eject_final_msg" "$which" "$disc"
			screenlog "  $eject_final_prompt" "$zonename" "[y]/n"

			read ans && [[ "$ans" = [Nn]* ]] && eject_final="N" &&
			    status=$(gettext "will NOT")

			screenlog "\n$eject_final_status\n" "$which" "$disc" \
			    "$status"
		fi

		screenlog "$install_ndiscs" "$distro_ncds"

		msg=$(gettext "install %s.")
		screenlog "$msg" "$release_name"
	else
		screenlog "$install_nisos" "$distro_ncds"

		msg=$(gettext "DVD) to install %s.")
		screenlog "$msg" "$release_name"
	fi

	install_from_media "$path"
	install_status=$?

	[[ "$eject_final" = "Y" ]] && eject_removable_disc

	return $install_status
}

#
# Install a zone using the list of ISO files passed as arguments to this
# function.
#
# Return 0 on success, 1 on failure.
#
do_iso_install()
{
	typeset install_status
	typeset iso_path
	typeset ldev

	msg=$(gettext "Checking for valid Linux distribution ISO images...")
	screenlog "\n$msg"

	scan_isos "$@"

	if [[ -z ${iso_filename[@]} ]]; then
		msg=$(gettext "No valid ISO images available or mountable.")
		screenlog "\n$msg"
		return 1
	fi
	
	validate_iso_distros

	if [[ -z ${release[@]} ]]; then
		msg=$(gettext "No supported Linux distributions found.")
		screenlog "\n$msg"
		return 1
	fi

	select_distro "${select_name[@]}" || return 1
	unset select_name

	. ${distro_file[$ndistro]} > /dev/null
	distro_ncds=${#distro_cdorder[@]}

	check_mbfree $zoneroot $distro_mb_required || return 1
	build_rpm_list $install_packages

	unset lofi_devs

	verboselog ""
	for iso_path in ${iso_set[$ndistro]}; do
		if ! lofi_add "$iso_path"; then
			for ldev in $lofi_devs; do
				lofi_del "$ldev"
			done
			return 1
		fi

		verboselog "Added \"$iso_path\""
		verboselog "  as \"$lofi_dev\""
		lofi_devs="$lofi_devs $lofi_dev"
	done

	release_name="${release[$ndistro]}"

	set -A iso_pathnames "zero_pad" ${iso_set[$ndistro]}
	install_from_media $lofi_devs
	install_status=$?

	for ldev in $lofi_devs; do
		lofi_del "$ldev"
	done

	unset lofi_devs
	return $install_status
}

# Clean up on interrupt
trap_cleanup()
{
	cd "$cwd"

	msg=$(gettext "Interrupt received, cleaning up partial install...")
	screenlog "$msg"

	[[ -n $miniroot_booted ]] && zoneadm -z "$zonename" halt &&
	    unset miniroot_booted && unset newroot_mounted

	#
	# OK, why a sync here?  Because certain commands may have written data
	# to mounted file systems before the interrupt, and given just the right
	# timing there may be buffered data not yet sent to the disk or the
	# system may still be writing data to the disk.  Either way, the umount
	# will then fail because the system will still see the mounted
	# filesystems as busy.
	#
	sync

	if [[ -n $newroot_mounted ]]; then
		umount_list $newroot_mounted
		unset newroot_mounted
	fi

	if [[ -n $zone_mounted ]]; then
		umount "$zone_mounted"
		unset zone_mounted
	fi

	#
	# Normally, this isn't needed but there is a window where mntdir is set
	# before zone_mounted, so account for that case.
	#
	if [[ -n $mntdir ]]; then
		umount "$mntdir"
		unset mntdir
	fi

	[[ -n $lofi_dev ]] && lofi_del "$lofi_dev"

	if [[ -n $lofi_devs ]]; then
		typeset ldev

		for ldev in $lofi_devs
		do
			lofi_del "$ldev"
		done

		unset lofi_devs
	fi

	[[ -n $lofi_created ]] && rmdir -ps "$lofi_created" &&
	    unset lofi_created

	msg=$(gettext "Installation aborted.")
	screenlog "$msg"
	exit $ZONE_SUBPROC_FATAL
}

#
# Start of main script
#
cwd=$(dirname "$0")
distro_dir="$cwd/distros"

unset deferred_saved
unset distro_path
unset logfile
unset msg
unset newroot_mounted
unset silent_err_msg
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
	msg=$(gettext "ERROR:  Cannot install - no zone name was specified")
	screenlog "$msg"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

if [[ -z $zoneroot ]]; then
	msg=$(gettext "ERROR:  Cannot install - no zone root directory was")
	screenlog "$msg"

	msg=$(gettext "specified.")
	screenlog "  $msg"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

# Make sure the specified zone root directory exists
[[ -d "$zoneroot" ]] || mkdir -m 0700 -p "$zoneroot"

if [[ ! -d "$zoneroot" ]]; then
	screenlog "$zone_rootfail" "$zoneroot"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

rootdir="$zoneroot/root"

# Make sure the specified zone root subdirectory exists
[[ -d "$rootdir" ]] || mkdir -p "$rootdir"

if [[ ! -d "$rootdir" ]]; then
	screenlog "$zone_rootsub" "$rootdir"
	echo
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

media_mntdir="$rootdir/media"

if [[ -n $logfile ]]; then
	# If a log file was specified, log information regarding the install
	log "\nInstallation started `date`" 
	log "Installing from path \"$distro_path\""
else
	# Redirect stderr to /dev/null if silent mode is specified.
	[[ -n $silent_mode ]] && exec 2>/dev/null
fi

distro_path=${distro_path:=$default_distro_path}

# From this point on, call trap_cleanup() on interrupt (^C)
trap trap_cleanup INT

verbose "Installing zone \"$zonename\" at root \"$zoneroot\""
release_name="supported Linux distribution"

#
# Based on the pathname, attempt to determine whether this will be a disc or
# lofi-based install or one using ISOs.
#
if [[ "$distro_path" = /cdrom/* || "$distro_path" = /media/* ||
    "$distro_path" = /dev/dsk/* || "$distro_path" = /dev/lofi/* ]]; then
	if [[ "$distro_path" = /dev/lofi/* ]]; then
		silent_err_msg="$silent_nolofi"
		install_media="lofi"
	else
		silent_err_msg="$silent_nodisc"
		install_media="disc"
	fi

	if [[ "$distro_path" = /cdrom/* || "$distro_path" = /media/* ]]; then
		managed_removable=1
	else
		managed_removable=0
	fi

	log "Installing zone \"$zonename\" at root \"$zoneroot\""
	verboselog "  Attempting ${install_media}-based install via:"
	verboselog "    \"$distro_path\""

	do_disc_install "$distro_path"
else
	typeset dir_start
	typeset dir_file

	dir_start=$(dirname "$distro_path" | cut -c 1)

	[[ "$dir_start" != "/" ]] && distro_path="${PWD:=$(pwd)}/$distro_path"

	if [[ ! -d "$distro_path" ]]; then
		screenlog "$no_distropath" "$distro_path"
		echo
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi

	log "Installing zone \"$zonename\" at root \"$zoneroot\""
	verboselog "  Attempting ISO-based install from directory:"
	verboselog "    \"$distro_path\""

	unset iso_files

	for dir_file in $distro_path/*; do
		#
		# Skip this file if it's not a regular file or isn't readable
		#
		[[ ! -f $dir_file || ! -r $dir_file ]] && continue

		#
		# If it's an hsfs file, it's an ISO, so add it to the possible
		# distro ISO list
		#
		filetype=$(LC_ALL=C fstyp $dir_file 2>/dev/null) &&
		    [[ "$filetype" = "hsfs" ]] &&
		    iso_files="$iso_files $dir_file"
	done

	install_media="ISO"
	do_iso_install $iso_files
fi

if [[ $? -ne 0 ]]; then
	cd "$cwd"

	[[ -n $miniroot_booted ]] && zoneadm -z "$zonename" halt &&
	    unset miniroot_booted && unset newroot_mounted

	if [[ -n $zone_mounted ]]; then
		umount "$zone_mounted"
		unset zone_mounted
	fi

	if [[ -n $newroot_mounted ]]; then
		umount_list $newroot_mounted
		unset newroot_mounted
	fi

	screenlog "\n$install_failed\n" "$release_name" "$zonename" "`date`"

	msg=$(gettext "Cleaning up after failed install...")
	screenlog "$msg"

	#
	# The extra checks are some basic paranoia due to the potentially
	# dangerous nature of these commands but are not intended to catch all
	# malicious cases.
	#
	[[ -d "$zoneroot/a" ]] && rm -rf "$zoneroot/a"

	exit $ZONE_SUBPROC_FATAL
fi

screenlog "$install_done" "$release_name" "$zonename" "`date`"

exit $ZONE_SUBPROC_OK
