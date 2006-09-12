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
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Restrict executables to /bin, /usr/bin and /usr/sfw/bin
#
PATH=/bin:/usr/bin:/usr/sfw/bin
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

cmd_not_found=$(gettext "Required command '%s' cannot be found!")
cmd_not_exec=$(gettext "Required command '%s' not executable!")
zone_initfail=$(gettext "Attempt to initialize zone '%s' FAILED.")
path_abs=$(gettext "Pathname specified to -d '%s' must be absolute.")

usage_iso=$(gettext "ISO images located in the directory %s")

cmd_h=$(gettext "%s -z <zone name> %s -h")
cmd_full=\
$(gettext "%s -z <zone name> %s [-v | -s] [-d <archive dir>] [<cluster> ... ]")

both_modes=$(gettext "%s: error: cannot select both silent and verbose modes")

not_found=$(gettext "'%s': file not found.")
unknown_type=$(gettext "'%s': unknown type of file.")
wrong_type=$(gettext "'%s': wrong type of file.")
not_readable=$(gettext "Cannot read file '%s'")

no_install=$(gettext "Could not create install directory '%s'")
no_log=$(gettext "Could not create log directory '%s'")

install_zone=$(gettext "Installing zone '%s' at root directory '%s'")
install_from=$(gettext "from archive '%s'")

install_fail=$(gettext "Installation for zone '%s' FAILED.")
see_log=$(gettext "See the log file '%s' for details.")

install_good=$(gettext "Installation of zone '%s' completed successfully.")

#
# Check if commands passed in exist and are executable.
#
check_cmd()
{
	for cmd in "$@"; do
		if [[ ! -f $cmd ]]; then
			screenlog "$cmd_not_found" "$cmd"
			exit $ZONE_SUBPROC_NOTCOMPLETE
		fi

		if [[ ! -x $cmd ]]; then
			screenlog "$cmd_not_exec" "$cmd"
			exit $ZONE_SUBPROC_NOTCOMPLETE
		fi
	done
}

#
# Post process as tarball-installed zone for use by BrandZ.
#
init_tarzone()
{
	typeset rootdir="$1"

        if ! $branddir/lx_init_zone "$rootdir" "$logfile"; then
                screenlog "$zone_initfail" "$zonename"
                return 1
        fi
}

#
# Output a usage message
#
usage()
{
	echo $(gettext "Usage:")
	screenlog "$cmd_h" "zoneadm" "install"
	screenlog "$cmd_full" "zoneadm" "install"
	echo
	echo $(gettext "Linux archives can be in one of several forms:")
	echo
	echo $(gettext "    + A compressed tar archive")
	echo $(gettext "    + A set of CD-ROM or DVD discs")
	echo $(gettext "    + A group of ISO images")
	echo
	echo $(gettext "The install will attempt to use the default system")
	echo $(gettext "removable disc device if <archive dir> is not")
	echo $(gettext "specified.")
	echo
	echo $(gettext "<cluster> specifies which package cluster you wish")
	echo $(gettext "to install.  The desktop cluster will be installed")
	echo $(gettext "by default.")
	echo
	echo $(gettext "The available clusters are:")
	echo "    core"
	echo "    server"
	echo "    desktop"
	echo "    development"
	echo "    all"
	echo
	echo $(gettext "Each cluster includes all of the clusters preceding")
	echo $(gettext "it.  So, 'server' includes 'core', 'desktop' includes")
	echo $(gettext "'core' and 'server', and so on.")
	echo
	echo $(gettext "Examples")
	echo "========"
	echo $(gettext "Example 1:  Install a base Linux system from CD-ROM")
	echo $(gettext "discs using the system default removable disc device:")
	echo
	echo "    # zoneadm -z myzone install"
	echo
	echo $(gettext "Example 2:  Install the server packages from CD-ROM")
	echo $(gettext "via an alternative removable disc device:")
	echo
	echo "    # zoneadm -z myzone install -d /cdrom/cdrom0 server"
	echo
	echo $(gettext "Example 3:  Install the entire Linux environment from")
	screenlog "$usage_iso" "/export/images/centos_3.5/isos"
	echo
	echo "    # zoneadm -z myzone install -d" \
	    "/export/images/centos_3.5/isos all"
	echo
	echo $(gettext "Example 4:  Install from a compressed tar archive of")
	echo $(gettext "an existing Linux installation (a tar ball) with")
	echo $(gettext "verbose output regarding the progress of the")
	echo $(gettext "installation")
	echo
	echo "    # zoneadm -z myzone install -d /tmp/linux_full.tar.gz -v"
	echo
	echo $(gettext "Example 5:  Install from a compressed tar archive of")
	echo $(gettext "an existing Linux installation (a tar ball) with")
	echo $(gettext "NO output regarding the progress of the installation")
	echo $(gettext "(silent mode.)  Note that silent mode is only")
	echo $(gettext "recommended for use by shell scripts and programs.")
	echo
	echo "    # zoneadm -z myzone install -d /tmp/linux_full.tar.gz -s"
	echo
}

#
# The main body of the script starts here.
#
# This script should never be called directly by a user but rather should
# only be called by zoneadm to install a BrandZ Linux zone.
#

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
# If we weren't passed at least two arguments, exit now.
#
if [[ $# -lt 2 ]]; then
	usage

	exit $ZONE_SUBPROC_USAGE
fi

#
# This script is always started with a full path so we can extract the
# brand directory name here.
#
branddir=$(dirname "$0")
zonename="$1"
zoneroot="$2"

install_root="$zoneroot/root"
logdir="$install_root/var/log"

shift; shift	# remove zonename and zoneroot from arguments array

unset gtaropts
unset install_opts
unset install_src
unset silent_mode
unset verbose_mode

while getopts "d:hsvX" opt
do
	case "$opt" in
		h) 	usage; exit $ZONE_SUBPROC_USAGE ;;
		s)	silent_mode=1;;
		v)	verbose_mode=1;;
		d) 	install_src="$OPTARG" ;;
		X)	install_opts="$install_opts -x" ;;
		*)	usage ; exit $ZONE_SUBPROC_USAGE ;;
	esac
done
shift OPTIND-1

#
# The install can't be both verbose AND silent...
#
if [[ -n $silent_mode && -n $verbose_mode ]]; then
	screenlog "$both_modes" "zoneadm install"
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

if [[ -n $install_src ]]; then
	#
	# Validate $install_src.
	#
	# If install_src is a directory, assume it contains ISO images to
	# install from, otherwise treat the argument as if it points to a
	# tar ball file.
	#
	if [[ "`echo $install_src | cut -c 1`" != "/" ]]; then
		screenlog "$path_abs" "$install_src"
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi

	if [[ ! -a "$install_src" ]]; then
		screenlog "$not_found" "$install_src"
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi

	if [[ ! -r "$install_src" ]]; then
		screenlog "$not_readable" "$install_src"
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi

	if [[ ! -d "$install_src" ]]; then
		if [[ ! -f "$install_src" ]]; then
			screenlog "$wrong_type" "$install_src"
			exit $ZONE_SUBPROC_NOTCOMPLETE
		fi

		filetype=`{ LC_ALL=C; file $install_src | 
		    awk '{print $2}' ; } 2>/dev/null`

		if [[ "$filetype" = "gzip" ]]; then
			verbose "\"$install_src\": \"gzip\" archive"
			gtaropts="-xz"
		elif [[ "$filetype" = "bzip2" ]]; then
			verbose "\"$install_src\": \"bzip2\" archive"
			gtaropts="-xj"
		elif [[ "$filetype" = "compressed" ]]; then
			verbose "\"$install_src\": Lempel-Ziv" \
			    "compressed (\".Z\") archive."
			gtaropts="-xZ"
		elif [[ "$filetype" = "USTAR" ]]; then
			verbose "\"$install_src\":" \
			    "uncompressed (\"tar\") archive."
			gtaropts="-x"
		else
			screenlog "$unknown_type" "$install_src"
			exit $ZONE_SUBPROC_NOTCOMPLETE
		fi
	fi
fi

#
# Start silent operation and pass the flag to prepare pass the flag to
# the ISO installer, if needed.
#
if [[ -n $silent_mode ]]
then
	exec 1>/dev/null
	install_opts="$install_opts -s"
fi

#
# If verbose mode was specified, pass the verbose flag to lx_distro_install
# for ISO or disc installations and to gtar for tarball-based installs.
#
if [[ -n $verbose_mode ]]
then
	echo $(gettext "Verbose output mode enabled.")
	install_opts="$install_opts -v"
	[[ -n $gtaropts ]] && gtaropts="${gtaropts}v"
fi

[[ -n $gtaropts ]] && gtaropts="${gtaropts}f"

if [[ ! -d "$install_root" ]]
then
	if ! mkdir -p "$install_root" 2>/dev/null; then
		screenlog "$no_install" "$install_root"
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi
fi

if [[ ! -d "$logdir" ]]
then
	if ! mkdir -p "$logdir" 2>/dev/null; then
		screenlog "$no_log" "$logdir"
		exit $ZONE_SUBPROC_NOTCOMPLETE
	fi
fi

logfile="${logdir}/$zonename.install.$$.log"

exec 2>"$logfile"

log "Installation started for zone \"$zonename\" `/usr/bin/date`"

if [[ -n $gtaropts ]]; then
	check_cmd /usr/sfw/bin/gtar $branddir/lx_init_zone

	screenlog "$install_zone" "$zonename" "$zoneroot"
	screenlog "$install_from" "$install_src"
	echo
	echo $(gettext "This process may take several minutes.")
	echo

	( cd "$install_root" && gtar "$gtaropts" "$install_src" &&
	    $branddir/lx_init_zone "$install_root" "$logfile" &&
	    init_tarzone "$install_root" )

	res=$?
else
	check_cmd $branddir/lx_distro_install

	$branddir/lx_distro_install -z "$zonename" -r "$zoneroot" \
	    -d "$install_src" -l "$logfile" $install_opts "$@"

	res=$?

	if [ $res -eq $ZONE_SUBPROC_USAGE ]; then
		usage
		exit $ZONE_SUBPROC_USAGE
	fi
fi

if [[ $res -ne $ZONE_SUBPROC_OK ]]; then
	log "Installation failed for zone \"$zonename\" `/usr/bin/date`"

	screenlog "$install_fail" "$zonename"

	#
	# Only make a reference to the log file if one will exist after
	# zoneadm exits.
	#
	[[ $res -ne $ZONE_SUBPROC_NOTCOMPLETE ]] &&
	    screenlog "$see_log" "$logfile"

	exit $res
fi

log "Installation complete for zone \"$zonename\" `date`"
screenlog "$install_good" "$zonename"
echo $(gettext "Details saved to log file:")
echo "    \"$logfile\""
echo

exit $ZONE_SUBPROC_OK
