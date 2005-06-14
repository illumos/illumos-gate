#!/bin/ksh
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

usage() {
	echo "usage: perfcnt -[$optlet] utility [utility arguments]"
	echo "	-f <bindfromlist>"
	echo "		A colon seperated list of libraries that are to be"
	echo "		traced.  Only calls from these libraries will be"
	echo "		traced.  The default is to trace all calls."
	echo "	-t <bindtolist>"
	echo "		A colon seperated list of libraries that are to be"
	echo "		traced.  Only calls to these libraries will be"
	echo "		traced.  The default is to trace all calls."
	echo "	-l <perfcntlib>"
	echo "		Specify an alternate perfcnt.so to use."
}

bindto=""
bindfrom=""
perfcntlib32="/opt/SUNWonld/lib/32/perfcnt.so.1"
perfcntlib64="/opt/SUNWonld/lib/64/perfcnt.so.1"

optlet="f:t:l:"

if [[ $# -lt 1 ]]; then
	usage
	exit 1
fi

while getopts $optlet c
do
	case $c in
	f)
		bindfrom="$OPTARG"
		;;
	t)
		bindto="$OPTARG"
		;;
	l)
		perfcntlib32="$OPTARG"
		perfcntlib64="$OPTARG"
		;;
	\?)
		usage
		exit 1
		;;
	esac
done
shift `expr $OPTIND - 1`

#
# Build environment variables
#

PERFCNT_BINDTO="$bindto" \
PERFCNT_BINDFROM="$bindfrom" \
LD_AUDIT_32="$perfcntlib32" \
LD_AUDIT_64="$perfcntlib64" \
$*

exit 0
