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
# Copyright 2010 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

. /usr/lib/brand/shared/common.ksh

ZONENAME=""
ZONEPATH=""
# Default to 10GB diskset quota
ZQUOTA=10

while getopts "R:t:q:z:" opt
do
	case "$opt" in
		R)	ZONEPATH="$OPTARG";;
		t)	TMPLZONE="$OPTARG";;
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

# The install requires a template zone.
if [[ -z $TMPLZONE ]]; then
	print -u2 "Brand error: a zone template is required"
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
zfs list -H -t filesystem -o mountpoint,name | egrep "^$dname	" | \
    read mp PDS_NAME
[ -z "$PDS_NAME" ] && \
    print -u2 "Brand error: missing parent ZFS dataset for $dname"

# zoneadm already created the dataset but we want to use a clone, so first
# remove the one zoneadm created. 
zfs destroy $PDS_NAME/$ZONENAME

zfs snapshot $PDS_NAME/${TMPLZONE}@${ZONENAME}
zfs clone -o quota=${ZQUOTA}g $PDS_NAME/${TMPLZONE}@${ZONENAME} \
    $PDS_NAME/$ZONENAME

chmod 700 $ZONEPATH

egrep -s "netcfg:" $ZROOT/etc/passwd
if (( $? != 0 )); then
	echo "netcfg:x:17:65:Network Configuration Admin:/:" \
	    >> $ZROOT/etc/passwd
	echo "netcfg:*LK*:::::::" >> $ZROOT/etc/shadow
fi
egrep -s "netadm:" $ZROOT/etc/group
(( $? != 0 )) && echo "netadm::65:" >> $ZROOT/etc/group

# /etc/svc/profile was a symlink on some builds but now it needs to be
# a directory with some contents which we can get from the global zone
# if the template doesn't have it already.
[ -h $ZROOT/etc/svc/profile ] && rm -f $ZROOT/etc/svc/profile
if [ ! -d $ZROOT/etc/svc/profile ]; then
	mkdir $ZROOT/etc/svc/profile
	cd /etc/svc/profile
	find . -print | cpio -pdm $ZROOT/etc/svc/profile 2>/dev/null
fi

touch $ZROOT/var/log/courier.log

exit $ZONE_SUBPROC_OK
