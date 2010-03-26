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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# s10 boot script.
#
# The arguments to this script are the zone name and the zonepath.
#

. /usr/lib/brand/solaris10/common.ksh

ZONENAME=$1
ZONEPATH=$2
ZONEROOT=$ZONEPATH/root

arch=`uname -p`
if [ "$arch" = "i386" ]; then
	ARCH32=i86
        ARCH64=amd64
elif [ "$arch" = "sparc" ]; then
	# 32-bit SPARC not supported!
	ARCH32=
        ARCH64=sparcv9
else
        echo "Unsupported architecture: $arch" 
        exit 2
fi

#
# Run the s10_support boot hook.
#
/usr/lib/brand/solaris10/s10_support boot $ZONENAME
if (( $? != 0 )) ; then
        exit 1
fi

BRANDDIR=/.SUNWnative/usr/lib/brand/solaris10;
FILEDIR=$BRANDDIR/files;
EXIT_CODE=1

#
# Replace the specified file in the booting zone with a wrapper script that
# invokes s10_isaexec_wrapper.  This is a convenience function that reduces
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
	if [ ! -h $path_dname -a -d $path_dname ]; then
		safe_replace $ZONEROOT/$1 $BRANDDIR/s10_isaexec_wrapper $2 $3 \
		    remove
	fi
}

wrap_with_native() {
	safe_wrap $ZONEROOT/$1 $BRANDDIR/s10_isaexec_wrapper $2 $3
}

#
# Before we boot we validate and fix, if necessary, the required files within
# the zone.  These modifications can be lost if a patch is applied within the
# zone, so we validate and fix the zone every time it boots.
#

#
# BINARY REPLACEMENT
#
# This section of the boot script is responsible for replacing Solaris 10
# binaries within the booting zone with Nevada binaries.  This is a two-step
# process: First, the directory structure of the zone is validated to ensure
# that binary replacement will proceed safely.  Second, Solaris 10 binaries
# are replaced with Nevada binaries.
#
# Here's an example.  Suppose that you want to replace /usr/bin/zcat with the
# Nevada /usr/bin/zcat binary.  Then you should do the following:
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
# Details about the binary replacement procedure can be found in the Solaris 10
# Containers Developer Guide.
#

#
# STEP ONE
#
# Validate that the zone filesystem looks like we expect it to.
#
safe_dir /usr
safe_dir /usr/lib
safe_dir /usr/bin
safe_dir /usr/sbin
safe_dir /sbin

#
# STEP TWO
#
# Replace Solaris 10 binaries with Nevada binaries.
#

#
# Replace various network-related programs with native wrappers.
#
replace_with_native /sbin/ifconfig 0555 root:bin

#
# PSARC 2009/306 removed the ND_SET/ND_GET ioctl's for modifying
# IP/TCP/UDP/SCTP/ICMP tunables. If S10 ndd(1M) is used within an
# S10 container, the kernel will return EINVAL. So we need this.
#
replace_with_native /usr/sbin/ndd 0555 root:bin

#
# Replace automount and automountd with native wrappers.
#
if [ ! -h $ZONEROOT/usr/lib/fs/autofs -a -d $ZONEROOT/usr/lib/fs/autofs ]; then
	safe_replace $ZONEROOT/usr/lib/fs/autofs/automount \
	    $BRANDDIR/s10_automount 0555 root:bin remove
fi
if [ ! -h $ZONEROOT/usr/lib/autofs -a -d $ZONEROOT/usr/lib/autofs ]; then
	safe_replace $ZONEROOT/usr/lib/autofs/automountd \
	    $BRANDDIR/s10_automountd 0555 root:bin remove
fi

#
# The class-specific dispadmin(1M) and priocntl(1) binaries must be native
# wrappers, and we must have all of the ones the native zone does.  This
# allows new scheduling classes to appear without causing dispadmin and
# priocntl to be unhappy.
#
rm -rf $ZONEROOT/usr/lib/class
mkdir $ZONEROOT/usr/lib/class || exit 1

find /usr/lib/class -type d -o -type f | while read x; do
	[ -d $x ] && mkdir -p -m 755 $ZONEROOT$x
	[ -f $x ] && wrap_with_native $x 0555 root:bin
done

#
# END OF STEP TWO
#

#
# Replace add_drv and rem_drv with /usr/bin/true so that pkgs/patches which
# install or remove drivers will work.  NOTE: add_drv and rem_drv are hard
# linked to isaexec so we want to remove the current executable and
# then copy true so that we don't clobber isaexec.
#
filename=$ZONEROOT/usr/sbin/add_drv
[ ! -f $filename.pre_p2v ] && safe_backup $filename $filename.pre_p2v
rm -f $filename
safe_copy $ZONEROOT/usr/bin/true $filename

filename=$ZONEROOT/usr/sbin/rem_drv
[ ! -f $filename.pre_p2v ] && safe_backup $filename $filename.pre_p2v
rm -f $filename
safe_copy $ZONEROOT/usr/bin/true $filename

exit 0
