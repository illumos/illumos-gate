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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# Restrict executables to /bin, /usr/bin, /usr/sbin and /usr/sfw/bin
PATH=/bin:/usr/bin:/usr/sbin:/usr/sfw/bin

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

unsupported_cpu=\
$(gettext "ERROR: Cannot install branded zone: processor must be %s-compatible")

cmd_not_found=$(gettext "Required command '%s' cannot be found!")
cmd_not_exec=$(gettext "Required command '%s' not executable!")
zone_initfail=$(gettext "Attempt to initialize zone '%s' FAILED.")
path_abs=$(gettext "Pathname specified to -d '%s' must be absolute.")

cmd_h=$(gettext "%s -z <zone name> %s -h")
cmd_full=\
$(gettext "%s -z <zone name> %s [-v | -s] [-d <dir>|<device>] [<cluster> ... ]")

both_modes=$(gettext "%s: error: cannot select both silent and verbose modes")

not_found=$(gettext "%s: error: file or directory not found.")

wrong_type=\
$(gettext "%s: error: must be a gzip, bzip2, .Z or uncompressed tar archive.")

not_readable=$(gettext "Cannot read file '%s'")

no_install=$(gettext "Could not create install directory '%s'")
no_log=$(gettext "Could not create log directory '%s'")
no_logfile=$(gettext "Could not create log file '%s'")

install_zone=$(gettext "Installing zone '%s' at root directory '%s'")
install_from=$(gettext "from archive '%s'")

install_fail=$(gettext "Installation of zone '%s' FAILED.")
see_log=$(gettext "See the log file:\n  '%s'\nfor details.")

install_abort=$(gettext "Installation of zone '%s' aborted.")
install_good=$(gettext "Installation of zone '%s' completed successfully.")

# Check if commands passed in exist and are executable.
check_cmd()
{
	for cmd in "$@"; do
		if [[ ! -f $cmd ]]; then
			screenlog "$cmd_not_found" "$cmd"
			screenlog "$install_abort" "$zonename"
			exit $ZONE_SUBPROC_NOTCOMPLETE
		fi

		if [[ ! -x $cmd ]]; then
			screenlog "$cmd_not_exec" "$cmd"
			screenlog "$install_abort" "$zonename"
			exit $ZONE_SUBPROC_NOTCOMPLETE
		fi
	done
}

# Post process as tarball-installed zone for use by BrandZ.
init_tarzone()
{
	typeset rootdir="$1"

        if ! $branddir/lx_init_zone "$rootdir"; then
                screenlog "$zone_initfail" "$zonename"
                return 1
        fi
}

# Clean up on interrupt
trap_cleanup()
{
	msg=$(gettext "Installation cancelled due to interrupt.")

	screenlog "$msg"
	exit $int_code
}

#
# Output the usage message.
#
# This is done this way due to limitations in the way gettext strings are
# extracted from shell scripts and processed.  Use of this somewhat awkward
# syntax allows us to produce longer lines of text than otherwise would be
# possible without wrapping lines across more than one line of code.
#
usage()
{
	int_code=$ZONE_SUBPROC_USAGE

	echo $(gettext "Usage:")
	printf "  $cmd_h\n" "zoneadm" "install"
	printf "  $cmd_full\n" "zoneadm" "install"

	echo

	echo $(gettext "The installer will attempt to use the default system") \
	    $(gettext "removable disc device if <archive dir> is not") \
	    $(gettext "specified.") | fmt -80

	echo

	echo $(gettext "<cluster> specifies which package cluster you wish") \
	    $(gettext "to install.") | fmt -80

	echo
	echo $(gettext "The 'desktop' cluster will be installed by default.")
	echo
	echo $(gettext "The available clusters are:")
	echo "    + core"
	echo "    + server"
	echo "    + desktop"
	echo "    + development"
	echo "    + all"
	echo

	echo $(gettext "Each cluster includes all of the clusters preceding") \
	    $(gettext "it, so the 'server' cluster includes the 'core'") \
	    $(gettext "cluster, the 'desktop' cluster includes the 'core'") \
	    $(gettext "and 'server' clusters, and so on.") | fmt -80

	echo
	echo $(gettext "Examples")
	echo "========"

	echo $(gettext "Example 1: Install a base Linux system from CDs or a") \
	    $(gettext "DVD using the system default removable disc device:") |
	    fmt -80

	echo
	echo "    # zoneadm -z myzone install"
	echo

	echo $(gettext "Example 2: Install the 'server' cluster from CDs or") \
	    $(gettext "a DVD via an alternative removable disc device:") |
	    fmt -80

	echo
	echo "    # zoneadm -z myzone install -d /cdrom/cdrom1 server"
	echo

	echo $(gettext "Example 3: Install the desktop Linux environment") \
	    $(gettext "from an ISO image made available as '/dev/lofi/1' by") \
	    $(gettext "use of lofiadm(1M):") | fmt -80

	echo
	echo "    # zoneadm -z myzone install -d /dev/lofi/1 desktop"
	echo

	echo $(gettext "Example 4: Install the entire Linux environment from") \
	    $(gettext "ISO images located in the directory") \
	    "'/export/centos_3.8/isos':" | fmt -80

	echo
	echo "    # zoneadm -z myzone install -d /export/centos_3.8/isos all"
	echo

	echo $(gettext "Example 5: Install from a compressed tar archive of") \
	    $(gettext "an existing Linux installation (a tar ball) with") \
	    $(gettext "verbose output regarding the progress of the") \
	    $(gettext "installation:") | fmt -80

	echo
	echo "    # zoneadm -z myzone install -v -d /tmp/linux_full.tar.gz"
	echo

	echo $(gettext "Example 6: Install from a compressed tar archive of") \
	    $(gettext "an existing Linux installation (a tar ball) with NO") \
	    $(gettext "output regarding the progress of the installation") \
	    $(gettext "(silent mode.)") | fmt -80

	echo

	echo $(gettext "NOTE: Silent mode is only recommended for use by") \
	    $(gettext "shell scripts and other non-interactive programs:") |
	    fmt -80

	echo
	echo "    # zoneadm -z myzone install -d /tmp/linux_full.tar.gz -s"
	echo

	exit $int_code
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
# An unspecified exit or interrupt should exit with ZONE_SUBPROC_NOTCOMPLETE,
# meaning a user will not need to do an uninstall before attempting another
# install.
#
int_code=$ZONE_SUBPROC_NOTCOMPLETE

trap trap_cleanup INT

# If we weren't passed at least two arguments, exit now.
[[ $# -lt 2 ]] && usage

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
unset msg
unset silent_mode
unset verbose_mode

while getopts "d:hsvX" opt
do
	case "$opt" in
		h) 	usage;;
		s)	silent_mode=1;;
		v)	verbose_mode=1;;
		d) 	install_src="$OPTARG" ;;
		X)	install_opts="$install_opts -x" ;;
		*)	usage;;
	esac
done
shift OPTIND-1

# Providing more than one passed argument generates a usage message
if [[ $# -gt 1 ]]; then
	msg=$(gettext "ERROR: Too many arguments provided:")

	screenlog "$msg"
	screenlog "  \"%s\"" "$@"
	screenlog ""
	usage
fi

# Validate any free-form arguments
if [[ $# -eq 1 && "$1" != "core" && "$1" != "server" && "$1" != "desktop" &&
    "$1" != "development" && "$1" != "all" ]]; then
	msg=$(gettext "ERROR: Unknown cluster name specified: %s")

	screenlog "$msg" "\"$1\""
	screenlog ""
	usage
fi

# The install can't be both verbose AND silent...
if [[ -n $silent_mode && -n $verbose_mode ]]; then
	screenlog "$both_modes" "zoneadm install"
	screenlog ""
	usage
fi

#
# Validate that we're running on a i686-compatible CPU; abort the zone
# installation now if we're not.
#
procinfo=$(LC_ALL=C psrinfo -vp | grep family)

#
# All x86 processors in CPUID families 6 or 15 should be i686-compatible,
# assuming third party processor vendors follow AMD and Intel's lead.
#
if [[ "$procinfo" != *" x86 "* ]] ||
    [[ "$procinfo" != *" family 6 "* && "$procinfo" != *" family 15 "* ]] ; then
	screenlog "$unsupported_cpu" "i686"
	exit $int_code
fi

if [[ -n $install_src ]]; then
	#
	# Validate $install_src.
	#
	# If install_src is a directory, assume it contains ISO images to
	# install from, otherwise treat the argument as if it points to a tar
	# ball file.
	#
	if [[ "`echo $install_src | cut -c 1`" != "/" ]]; then
		screenlog "$path_abs" "$install_src"
		exit $int_code
	fi

	if [[ ! -a "$install_src" ]]; then
		screenlog "$not_found" "$install_src"
		screenlog "$install_abort" "$zonename"
		exit $int_code
	fi

	if [[ ! -r "$install_src" ]]; then
		screenlog "$not_readable" "$install_src"
		screenlog "$install_abort" "$zonename"
		exit $int_code
	fi

	#
	# If install_src is a block device, a directory, a possible device
	# created via lofiadm(1M), or the directory used by a standard volume
	# management daemon, pass it on to the secondary install script.
	#
	# Otherwise, validate the passed filename to prepare for a tar ball
	# install.
	#
	if [[ ! -b "$install_src" && ! -d "$install_src" &&
	    "$install_src" != /dev/lofi/* && "$install_src" != /cdrom/* &&
	    "$install_src" != /media/* ]]; then
		if [[ ! -f "$install_src" ]]; then
			screenlog "$wrong_type" "$install_src"
			screenlog "$install_abort" "$zonename"
			exit $int_code
		fi

		filetype=`{ LC_ALL=C file $install_src | 
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
			screenlog "$wrong_type" "$install_src"
			screenlog "$install_abort" "$zonename"
			exit $int_code
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
		exit $int_code
	fi
fi

if [[ ! -d "$logdir" ]]
then
	if ! mkdir -p "$logdir" 2>/dev/null; then
		screenlog "$no_log" "$logdir"
		exit $int_code
	fi
fi

logfile="${logdir}/$zonename.install.$$.log"

if ! > $logfile; then
	screenlog "$no_logfile" "$logfile"
	exit $int_code
fi

# Redirect stderr to the log file to automatically log any error messages
exec 2>>"$logfile"

#
# From here on out, an unspecified exit or interrupt should exit with
# ZONE_SUBPROC_FATAL, meaning a user will need to do an uninstall before
# attempting another install, as we've modified the directories we were going
# to install to in some way.
#
int_code=$ZONE_SUBPROC_FATAL

log "Installation started for zone \"$zonename\" `/usr/bin/date`"

if [[ -n $gtaropts ]]; then
	check_cmd /usr/sfw/bin/gtar $branddir/lx_init_zone

	screenlog "$install_zone" "$zonename" "$zoneroot"
	screenlog "$install_from" "$install_src"
	echo
	echo $(gettext "This process may take several minutes.")
	echo

	if ! ( cd "$install_root" && gtar "$gtaropts" "$install_src" ) ; then
		log "Error: extraction from tar archive failed."
	else
		if ! [[ -d "${install_root}/bin" &&
		    -d "${install_root}/sbin" ]]; then
			log "Error: improper or incomplete tar archive."
		else
			$branddir/lx_init_zone "$install_root" &&
			    init_tarzone "$install_root"

			#
			# Emit the same code from here whether we're
			# interrupted or exiting normally.
			#
			int_code=$?
		fi
	fi

	if [[ $int_code -eq ZONE_SUBPROC_OK ]]; then
		log "Tar install completed for zone '$zonename' `date`."
	else
		log "Tar install failed for zone \"$zonename\" `date`."

	fi
else
	check_cmd $branddir/lx_distro_install

	$branddir/lx_distro_install -z "$zonename" -r "$zoneroot" \
	    -d "$install_src" -l "$logfile" $install_opts "$@"

	#
	# Emit the same code from here whether we're interrupted or exiting
	# normally.
	#
	int_code=$?

	[[ $int_code -eq $ZONE_SUBPROC_USAGE ]] && usage
fi

if [[ $int_code -ne $ZONE_SUBPROC_OK ]]; then
	screenlog ""
	screenlog "$install_fail" "$zonename"
	screenlog ""

	#
	# Only make a reference to the log file if one will exist after
	# zoneadm exits.
	#
	[[ $int_code -ne $ZONE_SUBPROC_NOTCOMPLETE ]] &&
	    screenlog "$see_log" "$logfile"

	exit $int_code
fi

#
# After the install completes, we've likely moved a new copy of the logfile into
# place atop the logfile we WERE writing to, so if we don't reopen the logfile
# here the shell will continue writing to the old logfile's inode, meaning we
# would lose all log information from this point on.
#
exec 2>>"$logfile"

screenlog ""
screenlog "$install_good" "$zonename"
screenlog ""

echo $(gettext "Details saved to log file:")
echo "    \"$logfile\""
echo

exit $ZONE_SUBPROC_OK
