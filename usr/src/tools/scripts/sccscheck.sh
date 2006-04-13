#! /bin/ksh -p
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# Invoked when make thinks a source file is out of touch with SCCS.

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH


PATH=/usr/bin:/usr/ccs/bin

if [ $# -ne 1 ]; then
	echo "Usage: $0 filename" 1>&2
	exit 1
fi

file="$1"
if [ ! -f "$file" ]; then
	(echo "\n$0: error: Source file $file has gone missing!"
	echo "$0: error: Check for over-enthusiastic clobber rules\n") 1>&2
	exit 1
fi

w=warning
status=0

if [ ! -z "$SCCSCHECK_FAIL" ]; then
	w=error
	status=1
elif [ -z "$SCCSCHECK_WARN" ]; then
    	exit 0
fi

case "$file" in
/*)
	;;
*)
	file="./$file";;
esac

sfile="${file%/*}/SCCS/s.${file##*/}"

if [ "$sfile" -nt "$file" ]; then
	(echo "\n$0: $w: In $(pwd)"
	echo "$0: $w: $file is out of date:\n"
	echo "$0: $w: \c"
	ls -E $sfile
	echo "$0: $w: \c"
	ls -E $file
	echo "\n$0: $w: Run bringovercheck ${CODEMGR_WS} to fix this workspace.\n") 1>&2 
	exit $status
fi
exit 0
