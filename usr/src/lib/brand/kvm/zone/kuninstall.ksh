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
# Copyright (c) 2012, Joyent, Inc. All rights reserved.
# Use is subject to license terms.
#

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

. /usr/lib/brand/shared/common.ksh

ZONENAME=""
ZONEPATH=""

while getopts "FR:z:" opt
do
	case "$opt" in
		F)	;;
		R)	ZONEPATH="$OPTARG";;
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

# Get the dataset of the parent directory of the zonepath.
dname=${ZONEPATH%/*}
bname=${ZONEPATH##*/}
PDS_NAME=`mount | nawk -v p=$dname '{if ($1 == p) print $3}'`
if [[ -z "$PDS_NAME" ]]; then
	print -u2 "Brand error: missing parent ZFS dataset for $dname"
	exit $ZONE_SUBPROC_USAGE
fi

# Destroy snapshots we took when creating disks
for origin in $(zfs list -H -o name,origin -t volume \
    | grep "^${PDS_NAME}/${bname}-disk" \
    | grep -v '\-$' | cut -f2); do

    zfs destroy -rF ${origin} >/dev/null 2>&1
done

ORIGIN=`zfs get -H -ovalue  origin $PDS_NAME/$bname`

zfs destroy -rF $PDS_NAME/$bname/cores
zfs destroy -rF $PDS_NAME/$bname
[ "$ORIGIN" != "-" ] && zfs destroy -F $ORIGIN

rm -rf $ZONEPATH

exit $ZONE_SUBPROC_OK
