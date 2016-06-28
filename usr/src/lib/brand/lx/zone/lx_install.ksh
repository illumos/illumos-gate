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
	echo "	-s <absolute-pathname>	Path to ZFS send stream"
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

zfs recv -F $ZONEPATH_DS < $ZFS_SEED
# One Joyent-ism we need to clean up.
rmdir $ZONEPATH/cores

exit 0
