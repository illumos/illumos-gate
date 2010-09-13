#!/bin/ksh -p
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

PROG=`basename $0`
PATH=/opt/onbld/bin:$PATH export PATH
if [ -n "$BUILD_TOOLS" ]; then
	PATH=$BUILD_TOOLS/onbld/bin:$PATH export PATH
fi

CONF=tools/scripts/build_cscope.conf

#
# Print the provided failure message and exit with an error.
#
fail()
{
        echo $PROG: $@ > /dev/stderr
        exit 1
}

if [ $# -ne 1 ]; then
	echo "Usage: $PROG <env_file>"
	exit 1
fi

#
# Setup environment variables
#
if [ -f "$1" ]; then
	if [[ $1 = */* ]]; then
		. $1
	else
		. ./$1
	fi
elif [ -f "/opt/onbld/env/$1" ]; then
	. "/opt/onbld/env/$1"
else
	fail "cannot find env file as $1 or /opt/onbld/env/$1"
fi

[ -z "$SRC" ] && fail "\$SRC is not set"
[ ! -d "$SRC" ] && fail "\$SRC ($SRC) is not a directory"

#
# Despite our name, we actually build cscope, ctags, and etags
# cross-references.
#
cd $SRC
while read name flags dirs; do
      [ "$name" = "" -o "$name" = "#" ] && continue
      [ "$flags" = "\"\"" ] && flags=
      xref -c $dirs
      xref $flags $dirs || fail "cannot build $name cross-reference"
done < $CONF
