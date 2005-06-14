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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

usage() {
	echo "usage: sotruss [-F:-T:-o:-f] utility [utility arguments]"
	echo "	-F <bindfromlist>"
	echo "		A colon seperated list of libraries that are to be"
	echo "		traced.  Only calls from these libraries will be"
	echo "		traced.  The default is to trace calls from the"
	echo "		main executable."
	echo "	-T <bindtolist>"
	echo "		A colon seperated list of libraries that are to be"
	echo "		traced.  Only calls to these libraries will be"
	echo "		traced.  The default is to trace all calls."
	echo "	-o <outputfile>"
	echo "		sotruss output will be directed to 'outputfile'."
	echo "		by default it is placed on stdout."
	echo "	-f"
	echo "		Follow all children created by fork() and also"
	echo "		print truss output for the children.  This also"
	echo "		causes a 'pid' to be added to each truss output line."
}

bindto=""
bindfrom=""
outfile=""
noindentopt=""
trusslib32="/usr/lib/link_audit/32/truss.so.1"
trusslib64="/usr/lib/link_audit/64/truss.so.1"
pidopt=""
noexitopt="1"

optlet="eF:T:o:fl:i"

if [[ $# -lt 1 ]]; then
	usage
	exit 1
fi

while getopts $optlet c
do
	case $c in
	F)
		bindfrom="$OPTARG"
		;;
	T)
		bindto="$OPTARG"
		;;
	o)
		outfile="$OPTARG"
		;;
	l)
		trusslib32="$OPTARG"
		trusslib64="$OPTARG"
		;;
	f)
		pidopt="1"
		;;
	i)
		noindentopt="1"
		;;
	e)
		noexitopt=""
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

TRUSS_BINDTO="$bindto" \
TRUSS_BINDFROM="$bindfrom" \
TRUSS_OUTPUT="$outfile" \
TRUSS_PID="$pidopt" \
TRUSS_NOINDENT="$noindentopt" \
TRUSS_NOEXIT="$noexitopt" \
LD_AUDIT_32="$trusslib32" \
LD_AUDIT_64="$trusslib64" \
"$@"

exit 0
