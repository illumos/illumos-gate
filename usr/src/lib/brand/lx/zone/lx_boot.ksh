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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015, Joyent, Inc.
# Copyright 2017 ASS-Einrichtungssysteme GmbH, Inc.
#
# lx boot script.
#
# The arguments to this script are the zone name and the zonepath.
#

. /usr/lib/brand/shared/common.ksh

ZONENAME=$1
ZONEPATH=$2
ZONEROOT=$ZONEPATH/root

w_missing=$(gettext "Warning: \"%s\" is not installed in the global zone")

arch=`uname -p`
if [ "$arch" = "i386" ]; then
	ARCH32=i86
        ARCH64=amd64
else
        echo "Unsupported architecture: $arch"
        exit 2
fi

#
# Run the lx_support boot hook.
#
/usr/lib/brand/lx/lx_support boot $ZONEPATH $ZONENAME
if (( $? != 0 )) ; then
        exit 1
fi

BRANDDIR=/native/usr/lib/brand/lx;
EXIT_CODE=1

#
# Before we boot we validate and fix, if necessary, the required files within
# the zone.  These modifications can be lost if a patch or upgrade is applied
# within the zone, so we validate and fix the zone every time it boots.
#

#
# Determine the distro.
#
distro=""
if [[ $(zonecfg -z $ZONENAME info attr name=docker) =~ "value: true" ]]; then
	distro="docker"
elif [[ -f $ZONEROOT/etc/redhat-release ]]; then
	distro="redhat"
elif [[ -f $ZONEROOT/etc/lsb-release ]]; then
	if egrep -s Ubuntu $ZONEROOT/etc/lsb-release; then
		distro="ubuntu"
	elif [[ -f $ZONEROOT/etc/debian_version ]]; then
		distro="debian"
	fi
elif [[ -f $ZONEROOT/etc/debian_version ]]; then
	distro="debian"
elif [[ -f $ZONEROOT/etc/alpine-release ]]; then
	distro="busybox"
elif [[ -f $ZONEROOT/etc/SuSE-release ]]; then
	distro="suse"
fi

[[ -z $distro ]] && fatal "Unsupported distribution!"

#
# Perform distro-specific customization.
#
. $(dirname $0)/lx_boot_zone_${distro}

exit 0
