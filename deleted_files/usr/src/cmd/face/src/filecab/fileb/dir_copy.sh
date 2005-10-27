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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

# usage: dir_copy source destination
# no need to redirect stderr in this file, spawnv
set -e
pwd=`pwd`
if [ -n "$3" ]
then
	path="$2/$3"
else
	path="$2/`basename $1`"
fi
mkdir "$path" 2>/dev/null

# make sure path is absolute so we can get to it from "$1" directory

if [ `expr "$path" : '/.*' || :` = 0 ]
then
	path="$pwd/$path"
fi
cd "$1"
find . -print | cpio -pmud "$path"
