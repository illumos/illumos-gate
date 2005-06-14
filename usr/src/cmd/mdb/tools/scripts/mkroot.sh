#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

#
# Script to create an MDB "root" from a given set of BFU archives.  The root
# is created relative to the current directory, and the archive directory is
# specified as a parameter to this script.  For each set of archives we
# extract the complete set of /usr/include files and adb macros, as well as
# the 32-bit and 64-bit debugger libraries upon which mdb itself depends.
# The resulting tree of files can then be used as an argument to ``mdb -R''
# and for subsequent recompilation of MDB modules.
#

bfu_extract ()
{
	cpio_args='-idmu'
	archive_base=$1
	shift

	for archive in $archive_base $archive_base.gz; do
		[ -f $archive_dir/$archive ] || continue
		echo "+ extracting files from $archive ... \c"

		if [ `basename $archive .gz` != $archive ]; then
			gunzip -c $archive_dir/$archive | cpio $cpio_args "$@"
		else
			cpio $cpio_args "$@" < $archive_dir/$archive
		fi
		return $?
	done
	return 1
}

mk_dirs()
{
	for d in $*; do
		if [ ! -d $d ]; then
			echo "+ mkdir -p $d"
			mkdir -p $d
		fi
	done
}

if [ $# -ne 1 ] || [ ! -d "$1" ]; then
	echo "Usage: `basename $0` bfu-archive-dir"
	exit 2
fi

PATH="$PATH:/ws/on81-gate/public/bin/`uname -p`"; export PATH
archive_dir=$1
umask 022

#
# Extract the files we need from the generic archive, and abort if no generic
# archive was found.  Note that we also specify 64-bit library patterns here;
# cpio will just silently ignore them if this happens to be an i386 archive.
#
bfu_extract generic.usr "usr/lib/adb/*" "usr/lib/mdb/*" "usr/include/*" \
    "usr/lib/libctf.so*" "usr/lib/sparcv9/libctf.so*" \
    "usr/lib/libkvm.so*" "usr/lib/sparcv9/libkvm.so*" \
    "usr/lib/libproc.so*" "usr/lib/sparcv9/libproc.so*" \
    "usr/lib/librtld_db.so*" "usr/lib/sparcv9/librtld_db.so*" \
    "usr/lib/libthread_db.so*" "usr/lib/sparcv9/libthread_db.so*" \
    "usr/lib/lwp/libthread_db.so*" "usr/lib/lwp/sparcv9/libthread_db.so*" \
    "usr/bin/mdb" "usr/bin/*/mdb"

if [ $? -ne 0 ]; then
	echo "`basename $0`: Failed to locate or extract generic.usr" >& 2
	exit 1
fi

for mach in sun4u i86pc; do
	bfu_extract $mach.usr "usr/platform/SUNW,*" \
	    "usr/platform/$mach/lib/adb/*" \
	    "usr/platform/$mach/lib/mdb/*" \
	    "usr/platform/$mach/include/*"
done

for platusr in `ls -1 $archive_dir | grep '^SUNW,.*\.usr'`; do
	bfu_extract $platusr "usr/platform/SUNW,*"
done

exit 0
