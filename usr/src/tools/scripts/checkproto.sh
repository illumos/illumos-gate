#!/bin/ksh -e
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
MACH=`uname -p`
PLIST=/tmp/protolist.$$

usage() {
	echo "usage: $0 <workspace>"
	exit 1
}

OPTIND=1
while getopts X flag
do
	case $flag in
	*)	usage
		;;
	esac
done

shift `expr $OPTIND - 1`

if [ $# = 0 -a "${CODEMGR_WS}" != "" ]; then
	WS=${CODEMGR_WS}
elif [ $# -ne 1 ]; then
	usage
else
	WS=$1
fi


GUFLAG="-gu"
if [ "${NIGHTLY_OPTIONS%o*}" != "$NIGHTLY_OPTIONS" ]; then
	GUFLAG=
fi

if [ ! -d ${WS} ]; then
	echo "${WS} is not a workspace"
	exit 1
fi

if [ -z "${SRC}" ]; then
	SRC=${WS}/usr/src
fi

PROTO=${WS}/proto/root_${MACH}

rm -f $PLIST

pkglocns="${SRC}/pkgdefs"
[ -d ${SRC}/../closed/pkgdefs ] && pkglocns="$pkglocns ${SRC}/../closed/pkgdefs"

exceptions=""
pkgdefs=""
for p in $pkglocns; do
	efile="$p/etc/exception_list_${MACH}"
	[ -f $efile ] && exceptions="$exceptions -e $efile"
	pkgdefs="$pkgdefs -d $p"
done

protolist ${PROTO} > $PLIST
protocmp ${GUFLAG} $exceptions $pkgdefs ${PLIST}

rm -f $PLIST
