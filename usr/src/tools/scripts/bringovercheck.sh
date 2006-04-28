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

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

PATH=/usr/bin:/usr/ccs/bin

# yield an exit status and no other output
# /dev/null redirection guards against noise in the event that neither $1
# nor $2 exist
isnewer() {
	[ "$1" -nt "$2" ] && return 0
	[ "$1" -ot "$2" ] && return 1
	left=$(/bin/ls -E "$1" 2>/dev/null | awk '{print $7}')
	left=${left##*.}
	right=$(/bin/ls -E "$2" 2>/dev/null | awk '{print $7}')
	right=${right##*.}
	[ -z "$left" -o -z "$right" -o "$left" -gt "$right" ] && return 0
	return 1
}

if [ $# -ne 1 ]; then
	echo "Usage: $0 workspace" 1>&2
	exit 1
fi

CODEMGR_WS="$1"

if [ ! -d "${CODEMGR_WS}" ]; then
    	echo "${CODEMGR_WS}: not a directory" 1>&2
	echo "Usage: $0 workspace" 1>&2
	exit 1
fi

if [ ! -f "${CODEMGR_WS}"/Codemgr_wsdata/nametable ]; then
    	echo "${CODEMGR_WS}: not a workspace (no Codemgr_wsdata/nametable)" 1>&2
	echo "Usage: $0 workspace" 1>&2
	exit 1
fi

cd ${CODEMGR_WS} &&
tail +2 Codemgr_wsdata/nametable | 
while read file etc; do
    	file="./$file"
	sfile="${file%/*}/SCCS/s.${file##*/}"
	if isnewer "$sfile" "$file"; then
	    	ls -E "$sfile"
		ls -E "$file" 
		echo "reget $file:"
		# -G needed so file doesn't land in working dir.
		sccs get -G "$file" "$file"
	fi
done
