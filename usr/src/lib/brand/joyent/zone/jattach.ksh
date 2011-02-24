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
# Copyright 2011 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

. /usr/lib/brand/shared/common.ksh
. /usr/lib/brand/joyent/common.ksh

ZONENAME=""
ZONEPATH=""
# Default to 10GB diskset quota
ZQUOTA=10

while getopts "R:t:U:q:z:" opt
do
	case "$opt" in
		R)	ZONEPATH="$OPTARG";;
		q)	ZQUOTA="$OPTARG";;
		z)	ZONENAME="$OPTARG";;
		*)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
	esac
done
shift OPTIND-1

if [[ -z $ZONEPATH || -z $ZONENAME ]]; then
	print -u2 "Brand error: No zone path or name"
	exit $ZONE_SUBPROC_USAGE
fi

# The dataset quota must be a number.
case $ZQUOTA in *[!0-9]*)
	print -u2 "Brand error: The quota $ZQUOTA is not a number"
	exit $ZONE_SUBPROC_USAGE;;
esac

ZROOT=$ZONEPATH/root

# Get the dataset of the parent directory of the zonepath.
dname=${ZONEPATH%/*}
bname=${ZONEPATH##*/}
zfs list -H -t filesystem -o mountpoint,name | egrep "^$dname	" | \
    read mp PDS_NAME
[ -z "$PDS_NAME" ] && \
    print -u2 "Brand error: missing parent ZFS dataset for $dname"

final_setup

exit $ZONE_SUBPROC_OK
