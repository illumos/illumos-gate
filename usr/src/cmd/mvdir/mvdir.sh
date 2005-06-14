#!/sbin/sh
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
# Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"

if [ $# != 2 ]
then
  echo "Usage: mvdir fromdir newname" >&2
  exit 2
fi
if [ "$1" = . ]
then
	echo "mvdir: cannot move '.'" >&2
	exit 2
fi
f=`basename "$1"`
t="$2"
if [ -d "$t" ]
then
	t="$t"/"$f"
fi
if [ -f "$t"  -o -d "$t" ]
then
  echo "$t" exists >&2
  exit 1
fi
if [  ! -d "$1" ]
then
  echo "$1" must be a directory >&2
  exit 1
fi

# *** common path tests: The full path name for $1 must not
# *** 			 be an anchored substring of the full
# ***			 path name for $2

here=`pwd`
cd "$1"
from="`pwd`/"
lfrom=`expr "$from" : "$from"`

cd "$here"
mkdir "$t"		# see if we can create the directory
if [ $? != 0 ]
then
	exit
fi
cd "$t"
to=`pwd`
cd "$here"
rmdir "$t"

a=`expr "$to" : "$from"`
if [ "$a" = "$lfrom" ]
then
  echo arguments have common path >&2
  exit 1
fi
# ***

mv "$1" "$t"
