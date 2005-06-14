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
	echo "usage: symbindrep -[$optlet] utility"
	echo "	-f <bindfromlist>"
	echo "		A colon sperated list of libraries that will have"
	echo "		symbol references tracked.  Only symbol references"
	echo "		originating from these libraries will be tracked."
	echo "		The default is to track symbol references from"
	echo "		all libraries."
	echo "	-t <bindtolist>"
	echo "		A colon separated list of libraries to track"
	echo "		symbol bindings.  Only bindings to objects in"
	echo "		these objects will be tracked.  The default is to"
	echo "		track bindings to all objects."
	echo "	-l <bindreplib>"
	echo "		specify an alternate symbindrep.so to use."
}

bindto=""
bindfrom=""
symbindreplib32="/opt/SUNWonld/lib/32/symbindrep.so.1"
symbindreplib64="/opt/SUNWonld/lib/64/symbindrep.so.1"

optlet="f:t:l:"

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
		symbindreplib32="$OPTARG"
		symbindreplib64="$OPTARG"
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

SYMBINDREP_BINDTO="$bindto" \
SYMBINDREP_BINDFROM="$bindfrom" \
LD_BIND_NOW=1 \
LD_AUDIT_32="$symbindreplib32" \
LD_AUDIT_64="$symbindreplib64" \
$*

exit 0
