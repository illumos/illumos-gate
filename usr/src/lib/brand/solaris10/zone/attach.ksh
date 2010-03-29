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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. /usr/lib/brand/solaris10/common.ksh

m_attach_log=$(gettext "Log File: %s")
m_zfs=$(gettext "A ZFS file system was created for the zone.")
m_attaching=$(gettext "Attaching...")
m_usage=$(gettext  "solaris10 brand usage:\n\tattach [-a archive | -d directory | -r recv_type]\n\tThe -a archive option specifies an archive name which can be a flar,\n\ttar, pax or cpio archive.\n\tThe -d directory option specifies an existing directory.\n\tThe -r recv_type option specifies the type of archive to be read from\n\tstdin.")
m_complete=$(gettext "Attach complete.")

install_fail=$(gettext  "*** Attach FAILED ***")

f_n_unimpl=$(gettext "The -n option is not yet implemented.")
f_zfs=$(gettext "Error creating a ZFS file system (%s) for the zone.")
f_nodataset=$(gettext "Error: there is no ZFS file system for the zone.")
f_zfsdestroy=$(gettext "Error destroying ZFS file system %s.")

f_sanity_notzone=$(gettext "Error: this is a system image and not a zone image.")

f_baddir=$(gettext "Invalid '%s' directory within the zone")

# Clean up on interrupt
trap_cleanup()
{
	msg=$(gettext "Installation cancelled due to interrupt.")
	log "$msg"

	# umount any mounted file systems
	umnt_fs

	trap_exit
}

# If the attach failed then clean up the ZFS datasets we created.
trap_exit()
{
	if [[ $EXIT_CODE != $ZONE_SUBPROC_OK && "$install_media" != "-" ]]; then
		/usr/lib/brand/solaris10/uninstall $ZONENAME $ZONEPATH -F
	fi

	exit $EXIT_CODE
}

EXIT_CODE=$ZONE_SUBPROC_USAGE
install_media="-"

trap trap_cleanup INT
trap trap_exit EXIT

# If we weren't passed at least two arguments, exit now.
(( $# < 2 )) && exit $ZONE_SUBPROC_USAGE

ZONENAME="$1"
ZONEPATH="$2"
# XXX shared/common script currently uses lower case zonename & zonepath
zonename="$ZONENAME"
zonepath="$ZONEPATH"

shift; shift	# remove ZONENAME and ZONEPATH from arguments array

ZONEROOT="$ZONEPATH/root"
logdir="$ZONEROOT/var/log"

noexecute=0

unset inst_type

# Other brand attach options are invalid for this brand.
while getopts "a:d:nr:" opt; do
	case $opt in
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
		n)	noexecute=1 ;;
		r)
			if [[ -n "$inst_type" ]]; then
				fatal "$incompat_options" "$m_usage"
			fi
		 	inst_type="stdin"
			install_media="$OPTARG"
			;;
		?)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
		*)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
	esac
done
shift $((OPTIND-1))

if [[ $noexecute == 1 && -n "$inst_type" ]]; then
	fatal "$m_usage"
fi

if [ $noexecute -eq 1 ]; then
	#
	# The zone doesn't have to exist when the -n option is used, so do
	# this work early.
	#

	# XXX do the sw validation for solaris10 minimal patch level to ensure
	# everything will be ok.
	EXIT_CODE=$ZONE_SUBPROC_NOTCOMPLETE
	fatal "$f_n_unimpl"
fi

EXIT_CODE=$ZONE_SUBPROC_NOTCOMPLETE

if [[ -z "$inst_type" ]]; then
 	inst_type="directory"

elif [[ "$install_media" != "-" ]]; then
	#
	# If we're not using a pre-existing zone directory layout then create
	# the zone datasets and mount them.
	#
	unset DATASET
	pdir=$(/usr/bin/dirname $ZONEPATH)
	zds=$(/usr/sbin/zfs list -H -t filesystem -o name $pdir 2>/dev/null)
	if (( $? == 0 )); then
		pnm=$(/usr/bin/basename $ZONEPATH)
		/usr/sbin/zfs create "$zds/$pnm"
		if (( $? == 0 )); then
			vlog "$m_zfs"
			DATASET="$zds/$pnm"
		else
			log "$f_zfs" "$zds/$pnm"
		fi
	fi

	create_active_ds
fi

#
# The zone's datasets are now in place, validate that things
# are setup correctly.
#

get_zonepath_ds $zonepath

/usr/sbin/zfs list -H -o name $ZONEPATH_DS/ROOT >/dev/null 2>&1
(( $? != 0 )) && fail_fatal "$f_no_active_ds"

zfs set mountpoint=legacy $ZONEPATH_DS/ROOT >/dev/null 2>&1
zfs set zoned=on $ZONEPATH_DS/ROOT >/dev/null 2>&1

get_active_ds $ZONEPATH_DS
zfs list -H -o name $ACTIVE_DS >/dev/null 2>&1
(( $? != 0 )) && fail_fatal "$f_zfs_create"

zfs set canmount=noauto $ACTIVE_DS >/dev/null 2>&1
zfs inherit mountpoint $ACTIVE_DS >/dev/null 2>&1
zfs inherit zoned $ACTIVE_DS >/dev/null 2>&1

if [ ! -d $ZONEROOT ]; then
	mkdir -p $ZONEROOT || fail_fatal "$f_mkdir" "$ZONEROOT"
	chmod 700 $ZONEPATH || fail_fatal "$f_chmod" "$ZONEPATH"
fi

mnted=`zfs get -H mounted $ACTIVE_DS | cut -f3`
if [[ $mnted = "no" ]]; then
	mount -F zfs $ACTIVE_DS $ZONEROOT || fail_fatal "$f_zfs_mount"
fi

LOGFILE=$(/usr/bin/mktemp -t -p /var/tmp $zonename.attach_log.XXXXXX)
if [[ -z "$LOGFILE" ]]; then
	fatal "$e_tmpfile"
fi
exec 2>>"$LOGFILE"
log "$m_attach_log" "$LOGFILE"

log "$m_attaching"
install_image "$inst_type" "$install_media"

mk_zone_dirs

#
# Perform a final check that this is really a zone image and not an archive of
# a system image which would need p2v.  Check for a well-known S10 SMF service
# that shouldn't exist in a zone.
#
if [[ -e $ZONEROOT/var/svc/manifest/system/sysevent.xml ]]; then
	log "$f_sanity_notzone"
	exit $ZONE_SUBPROC_NOTCOMPLETE
fi

EXIT_CODE=$ZONE_SUBPROC_OK

log "$m_complete"

zone_logfile="${logdir}/$zonename.attach$$.log"

safe_dir /var
safe_dir /var/log
safe_copy $LOGFILE $zone_logfile

log "$m_attach_log" "$zone_logfile"
rm -f $LOGFILE

exit $ZONE_SUBPROC_OK
