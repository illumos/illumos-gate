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

final_setup()
{
    ZRAM=$(zonecfg -z ${ZONENAME} info attr name=ram | \
        grep "value: " | cut -d ':' -f2 | tr -d ' ')

    if [[ -z ${ZRAM} ]]; then
        echo "Unable to find RAM value for VM"
	exit $ZONE_SUBPROC_FATAL
    fi

    CORE_QUOTA=$(((${ZRAM} * 2) + 256))

    # Convert quota to MB and use 10% of that value for the zone core dump
    # dataset.
    if [ ! -d $ZONEPATH/cores ]; then
        zfs create -o quota=${CORE_QUOTA}m -o compression=gzip \
           $PDS_NAME/$bname/cores
    fi
}
