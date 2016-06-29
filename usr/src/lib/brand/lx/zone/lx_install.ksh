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

bad_usage() {
	echo "LX zone install bad option"
	echo "Available options are:"
	echo "	-s <absolute-pathname>	Path to ZFS send stream or gzip thereof"
	exit $ZONE_SUBPROC_USAGE
}

while getopts "R:s:z:" opt
do
	case "$opt" in
		R)	ZONEPATH="$OPTARG";;
		z)	ZONENAME="$OPTARG";;
		s)	ZFS_SEED="$OPTARG";;
		*)	bad_usage ;;
	esac
done
shift OPTIND-1

if [[ $ZFS_SEED == "" ]]; then
    echo "The -s <absolute-pathname> argument is required for LX installation."
    bad_usage
fi

# Set the ZONEPATH_DS variable so we know the zone's dataset.
get_zonepath_ds $ZONEPATH

# Do something based on whatever ZFS_SEED is.

if [[ ! -f $ZFS_SEED ]]; then
    echo "Seed file $ZFS_SEED not found."
    # XXX KEBE SAYS maybe we can eat a snapshot name here, or even a
    # Joyent-style UUID for direct snagging from Joyent's image
    # servers.
    bad_usage
fi

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

# One Joyent-ism we need to clean up.
rmdir $ZONEPATH/cores

exit 0
