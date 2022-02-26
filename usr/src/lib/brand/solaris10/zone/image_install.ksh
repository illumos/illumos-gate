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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. /usr/lib/brand/solaris10/common.ksh

m_usage=$(gettext "solaris10 brand usage:\n\tinstall -u | -p [-v | -s] -a archive | -d directory.\n\tThe -a archive option specifies an archive name which can be a flar,\n\ttar, pax or cpio archive.\n\tThe -d directory option specifies an existing directory.\n\tThe -u option unconfigures the zone, -p preserves the configuration.")

no_install=$(gettext "Could not create install directory '%s'")

product_vers=$(gettext  "       Product: %s")
install_vers=$(gettext  "     Installer: %s")
install_zone=$(gettext  "          Zone: %s")
install_path=$(gettext  "          Path: %s")
installing=$(gettext    "    Installing: This may take several minutes...")
no_installing=$(gettext "    Installing: Using pre-existing data in zonepath")
install_prog=$(gettext  "    Installing: %s")

install_fail=$(gettext  "        Result: *** Installation FAILED ***")
install_log=$(gettext   "      Log File: %s")

install_good=$(gettext  "        Result: Installation completed successfully.")

sanity_ok=$(gettext     "  Sanity Check: Passed.  Looks like a Solaris 10 system.")
sanity_fail=$(gettext   "  Sanity Check: FAILED (see log for details).")


p2ving=$(gettext        "Postprocessing: This may take a while...")
p2v_prog=$(gettext      "   Postprocess: ")
p2v_done=$(gettext      "        Result: Postprocessing complete.")
p2v_fail=$(gettext      "        Result: Postprocessing failed.")

root_full=$(gettext "Zonepath root %s exists and contains data; remove or move aside prior to install.")

media_missing=\
$(gettext "you must specify an installation source using '-a', '-d' or '-r'.\n%s")

cfgchoice_missing=\
$(gettext "you must specify -u (sys-unconfig) or -p (preserve identity).\n%s")

mount_failed=$(gettext "ERROR: zonecfg(8) 'fs' mount failed")

not_flar=$(gettext "Input is not a flash archive")
bad_flar=$(gettext "Flash archive is a corrupt")
unknown_archiver=$(gettext "Archiver %s is not supported")

# Clean up on interrupt
trap_cleanup()
{
	msg=$(gettext "Installation cancelled due to interrupt.")
	log "$msg"

	# umount any mounted file systems
	umnt_fs

	trap_exit
}

# If the install failed then clean up the ZFS datasets we created.
trap_exit()
{
	if (( $EXIT_CODE != $ZONE_SUBPROC_OK )); then
		/usr/lib/brand/solaris10/uninstall $ZONENAME $ZONEPATH -F
	fi

	exit $EXIT_CODE
}

#
# The main body of the script starts here.
#
# This script should never be called directly by a user but rather should
# only be called by zoneadm to install a s10 system image into a zone.
#

#
# Exit code to return if install is interrupted or exit code is otherwise
# unspecified.
#
EXIT_CODE=$ZONE_SUBPROC_USAGE

trap trap_cleanup INT
trap trap_exit EXIT

# If we weren't passed at least two arguments, exit now.
(( $# < 2 )) && exit $ZONE_SUBPROC_USAGE

ZONENAME="$1"
ZONEPATH="$2"
# XXX shared/common script currently uses lower case zonename & zonepath
zonename="$ZONENAME"
zonepath="$ZONEPATH"

ZONEROOT="$ZONEPATH/root"
logdir="$ZONEROOT/var/log"

shift; shift	# remove ZONENAME and ZONEPATH from arguments array

unset inst_type
unset msg
unset silent_mode
unset OPT_V

#
# It is worth noting here that we require the end user to pick one of
# -u (sys-unconfig) or -p (preserve config).  This is because we can't
# really know in advance which option makes a better default.  Forcing
# the user to pick one or the other means that they will consider their
# choice and hopefully not be surprised or disappointed with the result.
#
unset unconfig_zone
unset preserve_zone
unset SANITY_SKIP

while getopts "a:d:Fpr:suv" opt
do
	case "$opt" in
		a)
			if [[ -n "$inst_type" ]]; then
				fatal "$incompat_options" "$m_usage"
			fi
		 	inst_type="archive"
			install_media="$OPTARG"
			;;
		d)
			if [[ -n "$inst_type" ]]; then
				fatal "$incompat_options" "$m_usage"
			fi
		 	inst_type="directory"
			install_media="$OPTARG"
			;;
		F)	SANITY_SKIP=1;;
		p)	preserve_zone="-p";;
		r)
			if [[ -n "$inst_type" ]]; then
				fatal "$incompat_options" "$m_usage"
			fi
		 	inst_type="stdin"
			install_media="$OPTARG"
			;;
		s)	silent_mode=1;;
		u)	unconfig_zone="-u";;
		v)	OPT_V="-v";;
		*)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
	esac
done
shift OPTIND-1

# The install can't be both verbose AND silent...
if [[ -n $silent_mode && -n $OPT_V ]]; then
	fatal "$incompat_options" "$m_usage"
fi

if [[ -z $install_media ]]; then
	fatal "$media_missing" "$m_usage"
fi

# The install can't both preserve and unconfigure
if [[ -n $unconfig_zone && -n $preserve_zone ]]; then
	fatal "$incompat_options" "$m_usage"
fi

# Must pick one or the other.
if [[ -z $unconfig_zone && -z $preserve_zone ]]; then
	fatal "$cfgchoice_missing" "$m_usage"
fi

LOGFILE=$(/usr/bin/mktemp -t -p /var/tmp $ZONENAME.install_log.XXXXXX)
if [[ -z "$LOGFILE" ]]; then
	fatal "$e_tmpfile"
fi
zone_logfile="${logdir}/$ZONENAME.install$$.log"
exec 2>>"$LOGFILE"
log "$install_log" "$LOGFILE"

vlog "Starting pre-installation tasks."

#
# From here on out, an unspecified exit or interrupt should exit with
# ZONE_SUBPROC_NOTCOMPLETE, meaning a user will need to do an uninstall before
# attempting another install, as we've modified the directories we were going
# to install to in some way.
#
EXIT_CODE=$ZONE_SUBPROC_NOTCOMPLETE

create_active_ds

vlog "Installation started for zone \"$ZONENAME\""
install_image "$inst_type" "$install_media"

[[ "$SANITY_SKIP" == "1" ]] && touch $ZONEROOT/.sanity_skip

log "$p2ving"
vlog "running: p2v $OPT_V $unconfig_zone $ZONENAME $ZONEPATH"

#
# Run p2v.
#
# Getting the output to the right places is a little tricky because what
# we want is for p2v to output in the same way the installer does: verbose
# messages to the log file always, and verbose messages printed to the
# user if the user passes -v.  This rules out simple redirection.  And
# we can't use tee or other tricks because they cause us to lose the
# return value from the p2v script due to the way shell pipelines work.
#
# The simplest way to do this seems to be to hand off the management of
# the log file to the p2v script.  So we run p2v with -l to tell it where
# to find the log file and then reopen the log (O_APPEND) when p2v is done.
#
/usr/lib/brand/solaris10/p2v -l "$LOGFILE" -m "$p2v_prog" \
     $OPT_V $unconfig_zone $ZONENAME $ZONEPATH
p2v_result=$?
exec 2>>$LOGFILE

if (( $p2v_result == 0 )); then
	vlog "$p2v_done"
else
	log "$p2v_fail"
	log ""
	log "$install_fail"
	log "$install_log" "$LOGFILE"
	exit $ZONE_SUBPROC_FATAL
fi

# Add a service tag for this zone.
add_svc_tag "$ZONENAME" "install $inst_type `basename $install_media`"

log ""
log "$install_good" "$ZONENAME"

safe_dir /var
safe_dir /var/log
safe_copy $LOGFILE $zone_logfile

log "$install_log" "$zone_logfile"
rm -f $LOGFILE

# This needs to be set since the exit trap handler is going run.
EXIT_CODE=$ZONE_SUBPROC_OK

exit $ZONE_SUBPROC_OK
