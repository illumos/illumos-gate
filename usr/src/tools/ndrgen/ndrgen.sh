#!/bin/ksh -p
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# This is a wrapper script around the ndrgen compiler (ndrgen1).
# CC must be defined in the environment or on the command line.

NDRPROG="${0%/*}/ndrgen1"
INCDIR=${ROOT}/usr/include/smbsrv

PROGNAME=`basename $0`

ndrgen_usage()
{
	if [[ $1 != "" ]] ; then
		print "$PROGNAME: ERROR: $1"
	fi

	echo "usage: $PROGNAME [-Y cpp-path] file [file]..."
	exit 1
}

if [[ $# -lt 1 ]] ; then
	ndrgen_usage
fi

while getopts "Y" FLAG $*; do
	case $FLAG in
	Y)
		CC_FLAG="y"
		;;
	*)
		ndrgen_usage
		;;
	esac
done

if [[ $CC_FLAG = "y" ]] ; then
	shift $(($OPTIND - 1))

	if [[ $# -lt 1 ]] ; then
		ndrgen_usage "C pre-processor path is missing"
	else
		CC=$1
		shift $(($OPTIND - 1))

		# Check for cw being invoked with -_cc
		if [[ $1 = "-_cc" ]] ; then
			CC_ARG=$1
			shift $(($OPTIND - 1))
		fi
	fi
fi

if [[ $CC = "" ]] ; then
	ndrgen_usage "C pre-processor is not defined"
fi

if [ ! -f $CC ] || [ ! -x $CC ] ; then
	ndrgen_usage "cannot run $CC"
fi

for i
do
	if [[ ! -r $i ]] ; then
		print "$PROGNAME: ERROR: cannot read $i"
		exit 1
	fi

	BASENAME=`basename $i .ndl`
	TMP_NAME=$BASENAME.ndl.c

	cp $i $TMP_NAME

	if $CC $CC_ARG -E  -D__a64 -D__EXTENSIONS__ -D_FILE_OFFSET_BITS=64 \
		-I. -I${INCDIR} -I${INCDIR}/ndl -DNDRGEN $TMP_NAME | \
		$NDRPROG > $BASENAME.raw
	then
		cat - << EOF > ${BASENAME}_ndr.c
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)${BASENAME}_ndr.c	1.2	07/01/07 SMI"

/*
 * THIS FILE IS GENERATED. DO NOT EDIT IT
 */
#include <strings.h>
#include <smbsrv/ndr.h>
#include <smbsrv/ndl/$BASENAME.ndl>
EOF

		cat $BASENAME.raw >> ${BASENAME}_ndr.c

		rm -f $BASENAME.raw
		rm -f $TMP_NAME
	else
		rm -f $BASENAME.raw
		rm -f $TMP_NAME
		exit 1
	fi
done
