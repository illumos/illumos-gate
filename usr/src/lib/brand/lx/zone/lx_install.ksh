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
# Copyright 2016 Joyent, Inc.  All rights reserved.
# Copyright 2016 OmniTI Computer Consulting, Inc.  All rights reserved.
#

PATH=/bin:/usr/bin:/usr/sbin
export PATH

. /usr/lib/brand/shared/common.ksh

ZFS_SEED=""
TAR_SEED=""

bad_usage() {
	echo "LX zone install bad option"
	echo "Available options are:"
	echo "	-s <absolute-pathname>	Path to ZFS send stream or gzip thereof"
	echo "	-t <absolute-pathname>	Path to tar archive or gzip thereof"
	exit $ZONE_SUBPROC_USAGE
}

while getopts "R:s:t:z:" opt
do
	case "$opt" in
		R)	ZONEPATH="$OPTARG";;
		z)	ZONENAME="$OPTARG";;
		s)	ZFS_SEED="$OPTARG";;
		t)	TAR_SEED="$OPTARG";;
		*)	bad_usage ;;
	esac
done
shift OPTIND-1

if [[ $ZFS_SEED == "" && $TAR_SEED == "" ]]; then
    echo "The -s <absolute-pathname> argument or the -t <absolute-pathname>"
    echo "argument is required for LX installation."
    bad_usage
fi

if [[ $ZFS_SEED != "" && $TAR_SEED != "" ]]; then
    echo "You must only specify one of -s or -t for LX installation."
    bad_usage
fi

# Set the ZONEPATH_DS variable so we know the zone's dataset.
get_zonepath_ds $ZONEPATH

# Do something based on whatever ZFS_SEED is.

if [[ -f $TAR_SEED ]]; then
    type=`file -b $TAR_SEED | awk '{print $1}'`
    if [[ $type == "gzip" ]]; then
	args="-xzf"
    else
	args="-xf"
    fi
    cd $ZONEPATH
    # Be very precise about permissions and ownership.
    mkdir -m 0755 dev
    chgrp sys dev
    mkdir -m 0755 root
    chgrp root sys
    cd root
    gtar $args $TAR_SEED
    exit 0
elif [[ ! -f $ZFS_SEED ]]; then
    # Try and eat a snapshot or a filesystem.
    outstr=`zfs list -Ht filesystem $ZFS_SEED 2>/dev/null | awk '{print $1}'`
    if [[ $outstr == $ZFS_SEED ]]; then
	# We have a zfs filesystem name.
	# Snapshot it using today's date/time
	snapname=`date -u "+%Y-%m-%d:%H:%M:%S"`
	ZFS_SEED=$ZFS_SEED@$snapname
	zfs snapshot $ZFS_SEED
	if [[ $? != 0 ]]; then
	    echo "ZFS snapshot ($ZFS_SEED) command failed ($?)."
	    exit $ZONE_SUBPROC_FATAL
	fi
	# else continue on with the new snapshot...
    fi

    outstr=`zfs list -Ht snapshot $ZFS_SEED 2>/dev/null | awk '{print $1}'`
    if [[ $outstr == $ZFS_SEED ]]; then
	# Hmmm, we found a snapshot name!
	echo "Cloning from snapshot $ZFS_SEED"
	# zoneadm already created $ZONEPATH_DS, destroy it before we clone.
	zfs destroy $ZONEPATH_DS
	zfs clone $ZFS_SEED $ZONEPATH_DS
	if [[ $? != 0 ]]; then
	    echo "ZFS clone ($ZFS_SEED to $ZONEPATH_DS) failed ($?)."
	    exit $ZONE_SUBPROC_FAIL
	fi
	# zfs promote $ZONEPATH_DS
	# if [[ $? != 0 ]]; then
	#    echo "ZFS promote ($ZONEPATH_DS) failed ($?)."
	#    exit $ZONE_SUBPROC_FAIL
	# fi
    else 
	echo "Seed file $ZFS_SEED $TAR_SEED not found."
	bad_usage
    fi
else
    type=`file -b $ZFS_SEED | awk '{print $1}'`

    # For now, we are dependent on the output of file(1).
    # I'm being cheesy in checking the first word of file(1)'s output.
    if [[ $type == "ZFS" ]]; then
	zfs recv -F $ZONEPATH_DS < $ZFS_SEED
    elif [[ $type == "gzip" ]]; then
	gunzip -c $ZFS_SEED | zfs recv -F $ZONEPATH_DS
    else
	echo "Seed file $ZFS_SEED not a ZFS receive (or compressed) one."
	bad_usage
    fi

    if [[ $? != 0 ]]; then
	echo "ZFS receive command failed ($?)."
	exit $ZONE_SUBPROC_FATAL
    fi
fi

# One Joyent-ism we need to clean up.
rmdir $ZONEPATH/cores
# And one we should probably adopt.
zfs set devices=off $ZONEPATH_DS

exit 0
