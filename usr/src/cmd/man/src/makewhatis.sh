#!/bin/sh -
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
# Copyright (c) 1998 by Sun Microsystems, Inc.
# All rights reserved
#
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved
#

# University Copyright- Copyright (c) 1982, 1986, 1988
# The Regents of the University of California
# All Rights Reserved
#
# University Acknowledgment- Portions of this document are derived from
# software developed by the University of California, Berkeley, and its
# contributors

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

PATH=/usr/xpg4/bin:$PATH

tmpdir=/tmp/whatis.$$
trap "rm -rf $tmpdir; exit 1" 1 2 13 15

mkdir -m 700 $tmpdir || {
	echo "${0}: could not create temporary directory" 1&>2
	exit 1
}

[ -d $1 ] || exit 1

cd $1
top=`pwd`
for i in man?* sman?*
do
	if [ -d $i ] ; then
		cd $i
		if test "`echo *`" != "*" ; then
			/usr/lib/getNAME *
		fi
		cd $top
	fi
done >$tmpdir/whatisx
sed  <$tmpdir/whatisx \
	-e 's/\\-/-/' \
	-e 's/\\\*-/-/' \
	-e 's/ VAX-11//' \
	-e 's/\\f[PRIB01234]//g' \
	-e 's/\\s[-+0-9]*//g' \
	-e '/ - /!d' \
	-e 's/.TH [^ ]* \([^ 	]*\).*	\(.*\) -/\2 (\1)	 -/' \
	-e 's/	 /	/g' | \
awk '{	title = substr($0, 1, index($0, "- ") - 1)
	synop = substr($0, index($0, "- "))
	count = split(title, n, " ")
	for (i=1; i<count; i++) {
		if ( (pos = index(n[i], ",")) || (pos = index(n[i], ":")) )
			n[i] = substr(n[i], 1, pos-1)
		printf("%s\t%s %s\t%s\n", n[i], n[1], n[count], synop)
	}
}' >$tmpdir/whatis
/usr/bin/expand -16,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88,92,96,100 \
	$tmpdir/whatis | LC_CTYPE=C LC_COLLATE=C sort | \
	/usr/bin/unexpand -a > windex
chmod 644 windex >/dev/null 2>&1
rm -rf $tmpdir
exit 0
