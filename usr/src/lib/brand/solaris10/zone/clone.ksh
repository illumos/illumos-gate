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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. /usr/lib/brand/solaris10/common.ksh

m_usage=$(gettext "solaris10 brand usage: clone {sourcezone}.")
f_nosource=$(gettext "Error: unable to determine source zone dataset.")
f_sysunconfig=$(gettext "Error: sys-unconfig failed.")

# Set up ZFS dataset hierarchy for the zone.

ROOT="rpool/ROOT"

# Other brand clone options are invalid for this brand.
while getopts "R:z:" opt; do
	case $opt in
		R)	ZONEPATH="$OPTARG" ;;
		z)	ZONENAME="$OPTARG" ;;
		*)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
	esac
done
shift $((OPTIND-1))

if [ $# -ne 1 ]; then
	fail_usage "$0 {sourcezone}";
fi

sourcezone=$1

# Find the active source zone dataset to clone.
sourcezonepath=`/usr/sbin/zonecfg -z $sourcezone info zonepath | \
    /usr/bin/cut -f2 -d' '`
if [ -z "$sourcezonepath" ]; then
	fail_fatal "$f_nosource"
fi

get_zonepath_ds $sourcezonepath
get_active_ds $ZONEPATH_DS

#
# Now set up the zone's datasets
#

#
# First make the top-level dataset.
#

pdir=`/usr/bin/dirname $ZONEPATH`
zpname=`/usr/bin/basename $ZONEPATH`

get_zonepath_ds $pdir
zpds=$ZONEPATH_DS

# Create the datasets.
/usr/sbin/zfs create $zpds/$zpname
if (( $? != 0 )); then
	fail_fatal "$f_zfs_create"
fi

/usr/sbin/zfs create -o mountpoint=legacy -o zoned=on $zpds/$zpname/ROOT
if (( $? != 0 )); then
	fail_fatal "$f_zfs_create"
fi

# make snapshot
SNAPNAME=${ZONENAME}_snap
SNAPNUM=0
while [ $SNAPNUM -lt 100 ]; do
	/usr/sbin/zfs snapshot $ACTIVE_DS@$SNAPNAME
        if [ $? = 0 ]; then
                break
	fi
	SNAPNUM=`expr $SNAPNUM + 1`
	SNAPNAME="${ZONENAME}_snap$SNAPNUM"
done

if [ $SNAPNUM -ge 100 ]; then
	fail_fatal "$f_zfs_create"
fi

# do clone
BENAME=zbe-0
/usr/sbin/zfs clone -o $PROP_ACTIVE=on -o canmount=noauto \
     $ACTIVE_DS@$SNAPNAME $zpds/$zpname/ROOT/$BENAME
if (( $? != 0 )); then
	fail_fatal "$f_zfs_create"
fi

if [ ! -d $ZONEPATH/root ]; then
	/usr/bin/mkdir -p $ZONEPATH/root || \
	    fail_fatal "$f_mkdir" "$ZONEPATH/root"
	/usr/bin/chmod 700 $ZONEPATH || \
	    fail_fatal "$f_chmod" "$ZONEPATH"
fi

# Don't re-sysunconfig if we've already done so
if [[ ! -f $ZONEROOT/etc/.UNCONFIGURED ]]; then
	/usr/sbin/zoneadm -z $ZONENAME boot -f -- -m milestone=none
	if (( $? != 0 )); then
		error "$e_badboot"
		fail_incomplete "$f_sysunconfig"
	fi

	sysunconfig_zone
	if (( $? != 0 )); then
		/usr/sbin/zoneadm -z $ZONENAME halt
		fail_incomplete "$f_sysunconfig"
	fi

	/usr/sbin/zoneadm -z $ZONENAME halt
fi

exit $ZONE_SUBPROC_OK
