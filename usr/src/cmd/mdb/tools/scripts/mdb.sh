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
# Copyright (c) 1998-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

mdb_lib=/net/mdb.eng/mdb/archives	# Archive library path
mdb_ws=/net/mdb.eng/mdb/snapshot/latest	# Snapshot of latest workspace
mdb_args=				# Debugger argument string

os_name='s81'				# Default OS name prefix
os_rel='5.9'				# Default OS release number

mach=`/usr/bin/uname -p`		# Machine type
unset mdb_exec build root		# Local variables

#
# Attempt to locate a suitable mdb binary to execute, first on the local
# machine, then in the user's workspace, and finally on the MDB server.
# If we select the user's workspace, we also set $root to their proto area
# to force MDB to use shared libraries installed there as well.
#
if [ -n "$CODEMGR_WS" -a -x $CODEMGR_WS/proto/root_$mach/usr/bin/mdb ]; then
	mdb_exec=$CODEMGR_WS/proto/root_$mach/usr/bin/mdb
	root=$CODEMGR_WS/proto/root_$mach
elif [ -x /usr/bin/mdb -a ! -d /mdb ]; then
	mdb_exec=/usr/bin/mdb
	root=$mdb_lib/$mach/%R/%V
elif [ -x /usr/bin/mdb -a -d /mdb ]; then
	for isa in `isalist`; do
		if [ -x /usr/bin/$isa/mdb ]; then
			mdb_exec=/usr/bin/$isa/mdb
			break
		fi
	done
	if [ -z "$mdb_exec" ]; then
		echo "$0: cannot find mdb binary in ISA subdirectories" >& 2
		exit 1
	fi
	root=$mdb_lib/$mach/%R/%V
elif [ -x $mdb_ws/proto/root_$mach/usr/bin/mdb ]; then
	mdb_exec=$mdb_ws/proto/root_$mach/usr/bin/mdb
	root=$mdb_lib/$mach/%R/%V
fi

#
# Abort if we were not able to locate a copy of mdb to execute.
#
if [ -z "$mdb_exec" ]; then
	echo "$0: failed to locate mdb executable" >& 2
	exit 1
fi

#
# The wrapper script handles several special command-line arguments that are
# used to select a desired set of MDB macros, modules, and a libkvm binary.
#
if [ $# -gt 0 ]; then
	case "$1" in
	-s[0-9]*)
		build=`echo "$1" | tr -d -`
		shift
		;;

	-[0-9]|-[0-9][0-9])
		build=`echo "$1" | tr -d -`
		if [ $build -lt 10 ]; then
			build=${os_name}_0$build
		else
			build=${os_name}_$build
		fi
		shift
		;;

	-[0-9][0-9]-|-[0-9][0-9][A-Za-z])
		build=${os_name}_`echo "$1" | cut -c2- | tr '[A-Z]' '[a-z]'`
		shift
		;;

	-B) build=$os_rel/Beta; shift ;;
	-U) build=$os_rel/Beta_Update; shift ;;
	-G) build=$os_rel/Generic; shift ;;

	-\?)
		echo "Usage: $0" \
		     "[ -s<rel> | -s<bld> | -[0-9]+ | -B | -G | -U ] args ..."

		echo "\t-s<rel>  Use proto area for specified release"
		echo "\t         e.g. -${os_name}"
		echo "\t-s<bld>  Use proto area for specified build"
		echo "\t         e.g. -${os_name}_01"
		echo "\t-[0-9]+  Use proto area for specified build of $os_name"
		echo "\t-B       Use proto area for $os_rel Beta build"
		echo "\t-G       Use proto area for $os_rel Generic build\n"
		echo "\t-U       Use proto area for $os_rel Beta_Update build"
		;;
	esac
fi

#
# If a build was specified, using the corresponding proto area from $mdb_lib.
# Note that this will override the $root setting determined above.
#
[ -n "$build" ] && root=$mdb_lib/$mach/$build

#
# If a proto area was set either by specifying a build number, or by using
# mdb from $CODEMGR_WS, set LD_LIBRARY_PATH accordingly.  This allows mdb to
# pick up the appropriate libkvm.so to examine dumps from that build.
# We also add the -R flag to the mdb command line so that mdb will modify
# its default macro include and module library paths to use the build root.
#
if [ -n "$build" -o "$root" = "$CODEMGR_WS/proto/root_$mach" ]; then
	if [ -n "$build" -a ! -d $root ]; then
		echo "mdb: $root is missing or not a directory" >& 2
		exit 1
	fi

	[ -n "$LD_LIBRARY_PATH" ] && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:
	LD_LIBRARY_PATH="$LD_LIBRARY_PATH$root/usr/lib"

	[ -n "$LD_LIBRARY_PATH_64" ] && LD_LIBRARY_PATH_64=$LD_LIBRARY_PATH_64:
	LD_LIBRARY_PATH_64="$LD_LIBRARY_PATH_64$root/usr/lib/sparcv9"

	export LD_LIBRARY_PATH LD_LIBRARY_PATH_64

elif [ $mdb_exec = $mdb_ws/proto/root_$mach/usr/bin/mdb ]; then
	#
	# We also need to set LD_LIBRARY_PATH if we're using mdb.eng's mdb
	# binary -- it requires the new libproc.so to work properly.
	#
	usrlib=$mdb_ws/proto/root_$mach/usr/lib

	[ -n "$LD_LIBRARY_PATH" ] && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:
	LD_LIBRARY_PATH="$LD_LIBRARY_PATH$usrlib"

	[ -n "$LD_LIBRARY_PATH_64" ] && LD_LIBRARY_PATH_64=$LD_LIBRARY_PATH_64:
	LD_LIBRARY_PATH_64="$LD_LIBRARY_PATH_64$usrlib/sparcv9"

	export LD_LIBRARY_PATH LD_LIBRARY_PATH_64
fi

exec $mdb_exec -R $root $mdb_args "$@"
