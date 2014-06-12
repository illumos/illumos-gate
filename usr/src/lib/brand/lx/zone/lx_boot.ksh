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
# Copyright 2014, Joyent, Inc. All rights reserved.
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
# Replace the specified file in the booting zone with a wrapper script that
# invokes lx_isaexec_wrapper.  This is a convenience function that reduces
# clutter and code duplication.
#
# Parameters:
#	$1	The full path of the file to replace (e.g., /sbin/ifconfig)
#	$2	The access mode of the replacement file in hex (e.g., 0555)
#	$3	The name of the replacement file's owner (e.g., root:bin)
#
# NOTE: The checks performed in the 'if' statement below are not generic: they
# depend on the success of the zone filesystem structure validation performed
# above to ensure that intermediate directories exist and aren't symlinks.
#
replace_with_native() {
	path_dname=$ZONEROOT/`dirname $1`

	[ ! -f $1 ] && printf "$w_missing" "$1"
	if [ ! -h $path_dname -a -d $path_dname ]; then
		safe_replace $ZONEROOT/$1 $BRANDDIR/lx_isaexec_wrapper $2 $3 \
		    remove
	fi
}

#
# Create a new wrapper script that invokes lx_isaexec_wrapper in the
# brand (for a non-existing Linux file) pointing to the native brand file.
#
# Parameters:
#	$1	The full path of the wrapper file to create
#	$2	The access mode of the replacement file in hex (e.g., 0555)
#	$3	The name of the replacement file's owner (e.g., root:bin)
#
wrap_with_native() {
	path_dname=$ZONEROOT/`dirname $1`
	cmd_name=`basename $1`
	if [ ! -h $path_dname -a -d $path_dname -a ! -f $ZONEROOT/$1 ]; then
		if [ -x /usr/lib/brand/lx/lx_$cmd_name ]; then
			safe_wrap $ZONEROOT/$1 $BRANDDIR/lx_$cmd_name \
			   $2 $3
		else
			safe_wrap $ZONEROOT/$1 $BRANDDIR/lx_isaexec_wrapper \
			   $2 $3
		fi
	fi
}

#
# Before we boot we validate and fix, if necessary, the required files within
# the zone.  These modifications can be lost if a patch or upgrade is applied
# within the zone, so we validate and fix the zone every time it boots.
#

#
# Determine the distro.
#
distro=""
if [[ -f $ZONEROOT/etc/redhat-release ]]; then
	distro="redhat"
elif [[ -f $ZONEROOT/etc/lsb-release ]]; then
	if egrep -s Ubuntu $ZONEROOT/etc/lsb-release; then
		distro="ubuntu"
	elif [[ -f $ZONEROOT/etc/debian_version ]]; then
		distro="debian"
	fi
elif [[ -f $ZONEROOT/etc/debian_version ]]; then
	distro="debian"
fi

[[ -z $distro ]] && fatal "Unsupported distribution!"

#
# BINARY REPLACEMENT
#
# This section of the boot script is responsible for replacing Linux
# binaries within the booting zone with native binaries.  This is a two-step
# process: First, the directory structure of the zone is validated to ensure
# that binary replacement will proceed safely.  Second, the Linux binaries
# are replaced with native binaries.
#
# Here's an example.  Suppose that you want to replace /usr/bin/zcat with the
# native /usr/bin/zcat binary.  Then you should do the following:
#
#	1.  Go to the section below labeled "STEP ONE" and add the following
#	    two lines:
#
#		safe_dir /usr
#		safe_dir /usr/bin
#
#	    These lines ensure that both /usr and /usr/bin are directories
#	    within the booting zone that can be safely accessed by the global
#	    zone.
#	2.  Go to the section below labeled "STEP TWO" and add the following
#	    line:
#
#		replace_with_native /usr/bin/zcat 0555 root:bin
#

#
# STEP ONE
#
# Validate that the zone filesystem looks like we expect it to.
#
safe_dir /sbin
safe_dir /etc
safe_dir /etc/init
safe_dir /etc/update-motd.d

#
# STEP TWO
#
# Replace Linux binaries with native binaries.
#
replace_with_native /sbin/ifconfig 0555 root:bin

#
# STEP THREE
#
# Perform distro-specific customization.
#
. $(dirname $0)/lx_boot_zone_${distro}

#
# STEP FOUR
#
# Create native wrappers for illumos-only commands
#
wrap_with_native /sbin/dladm 0555 root:bin
wrap_with_native /sbin/ipmgmtd 0555 root:bin

exit 0
