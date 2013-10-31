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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# Quis custodiet ipsos custodies?

if [ -z "$SRC" ]; then
	SRC=$CODEMGR_WS/usr/src
fi

if [ -z "$CODEMGR_WS" -o ! -d "$CODEMGR_WS" -o ! -d "$SRC" ]; then
	echo "$0: must be run from within a workspace."
	exit 1
fi

cd $CODEMGR_WS || exit 1

# Use -b to tell this script to ignore derived (built) objects.
if [ "$1" = "-b" ]; then
	b_flg=y
fi

# Not currently used; available for temporary workarounds.
args="-k NEVER_CHECK"

# We intentionally don't depend on $MACH here, and thus no $ROOT.  If
# a proto area exists, then we use it.  This allows this script to be
# run against gates (which should contain both SPARC and x86 proto
# areas), build workspaces (which should contain just one proto area),
# and unbuilt workspaces (which contain no proto areas).
if [ "$b_flg" = y ]; then
	rootlist=
elif [ $# -gt 0 ]; then
	rootlist=$*
else
	rootlist="$CODEMGR_WS/proto/root_sparc $CODEMGR_WS/proto/root_i386"
fi

for ROOT in $rootlist
do
	case "$ROOT" in
	*sparc|*sparc-nd)
		arch=sparc
		;;
	*i386|*i386-nd)
		arch=i386
		;;
	*)
		echo "$ROOT has unknown architecture." >&2
		exit 1
		;;
	esac
	if [ -d $ROOT ]; then
		#
		# This is the old-style packaging exception list, from
		# the svr4-specific usr/src/pkgdefs
		#
		[ -f $SRC/pkgdefs/etc/exception_list_$arch ] && \
			validate_paths '-s/\s*'$arch'$//'  \
			    -e ^usr/include/ike/ -b $ROOT \
			    $args $SRC/pkgdefs/etc/exception_list_$arch
		#
		# These are the new-style packaging exception lists,
		# from the repository-wide exception_lists/ directory.
		#
		e="$CODEMGR_WS/exception_lists/packaging"
		for f in $e; do
			if [ -f $f ]; then
				nawk 'NF == 1 || /[ 	]\+'$arch'$/ { print; }' \
				    < $f | validate_paths -b $ROOT -n $f
			fi
		done
	fi
done

# Two entries in the findunref exception_list deal with things created
# by nightly.  Otherwise, this test could be run on an unmodifed (and
# unbuilt) workspace.  We handle this by flagging the one that is
# present only on a built workspace (./*.out) and the one that's
# present only after a run of findunref (./*.ref) with ISUSED, and
# disabling all checks of them.  The assumption is that the entries
# marked with ISUSED are always known to be good, thus the Latin quote
# at the top of the file.
#
# The exception_list is generated from whichever input files are appropriate
# for this workspace, so checking it obviates the need to check the inputs.

if [ -r $SRC/tools/findunref/exception_list ]; then
	validate_paths -k ISUSED -r -e '^\*' $SRC/tools/findunref/exception_list
fi

if [ -f $SRC/tools/opensolaris/license-list ]; then
	sed -e 's/$/.descrip/' < $SRC/tools/opensolaris/license-list | \
		validate_paths -n SRC/tools/opensolaris/license-list \
		    -e ^usr/closed
fi

# Finally, make sure the that (req|inc).flg files are in good shape.
# If SCCS files are not expected to be present, though, then don't
# check them.
if [ ! -d "$CODEMGR_WS/Codemgr_wsdata" ]; then
	f_flg='-f'
fi

validate_flg $f_flg -e ^usr/closed/

exit 0
