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
. /usr/lib/brand/joyent/common.ksh

SNGL_BASE=/zones/sngl_base.tar.gz

ZONENAME=""
ZONEPATH=""
# Default to 10GB diskset quota
ZQUOTA=10

if [[ ! -f $SNGL_BASE ]]; then
	print -u2 "Brand error: missing the SNGL install tar file"
	exit $ZONE_SUBPROC_FATAL
fi

while getopts "R:t:U:q:z:" opt
do
	case "$opt" in
		R)	ZONEPATH="$OPTARG";;
		t)	TMPLZONE="$OPTARG";;
			# UUID is only used in the postinstall script
		U)	UUID="$OPTARG";;
		q)	ZQUOTA="$OPTARG";;
		z)	ZONENAME="$OPTARG";;
		*)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
	esac
done
shift OPTIND-1

if [[ -n $(zonecfg -z "${ZONENAME}" info attr name=transition \
    | grep "value: receiving:") ]]; then

    # Here we're doing an install for a received zone, the dataset should have
    # already been created.
    exit $ZONE_SUBPROC_OK
fi

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
bname=${ZONEPATH##*/}
PDS_NAME=`mount | nawk -v p=$dname '{if ($1 == p) print $3}'`
[ -z "$PDS_NAME" ] && \
    print -u2 "Brand error: missing parent ZFS dataset for $dname"

# We expect that zoneadm was invoked with '-x nodataset', so it won't have
# created the dataset.

QUOTA_ARG=
if [[ ${ZQUOTA} != "0" ]]; then
    QUOTA_ARG="-o quota=${ZQUOTA}g"
fi

zfs snapshot $PDS_NAME/${TMPLZONE}@${bname}
zfs clone -F ${QUOTA_ARG} $PDS_NAME/${TMPLZONE}@${bname} \
    $PDS_NAME/$bname || fatal "failed to clone zone dataset"

# Make sure zoneinit is setup to use -o xtrace, this handles old datasets where
# is not yet enabled by default.
if [[ -f ${ZROOT}/root/zoneinit && -z $(grep "^set -o xtrace" ${ZROOT}/root/zoneinit) ]]; then
    sed -i "" -e "s/^#set -o xtrace/set -o xtrace/" ${ZROOT}/root/zoneinit
fi

if [ ! -d ${ZONEPATH}/config ]; then
    mkdir -p ${ZONEPATH}/config
    chmod 755 ${ZONEPATH}/config
fi

final_setup

# Modify to make it a SNGL zone
rm -f $ZROOT/bin
ln -s /system/usr/bin $ZROOT/bin

(cd $ZROOT; rm -rf usr; gzcat $SNGL_BASE | tar xbf 512 -)

exit $ZONE_SUBPROC_OK
