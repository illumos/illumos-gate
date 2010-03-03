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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# Builds bfu archives. If no arguments, uses the environment variables
# already set (by bldenv). One argument specifies an environment file
# like nightly or bldenv uses.

USAGE='Usage: $0 [ <env_file> ]'

if [ $# -gt 1 ]; then
	echo $USAGE >&2
	exit 1
fi

if [ $# -eq 1 ]; then
	if [ -z "$OPTHOME" ]; then
		OPTHOME=/opt
		export OPTHOME
	fi
	#
	#       Setup environmental variables
	#
	if [ -f $1 ]; then
		if [[ $1 = */* ]]; then
			. $1
		else
			. ./$1
		fi
	else
		if [ -f $OPTHOME/onbld/env/$1 ]; then
			. $OPTHOME/onbld/env/$1
		else
			echo "Cannot find env file as either $1 \c" >&2
			echo "or $OPTHOME/onbld/env/$1" >&2
			exit 1
		fi
	fi
fi

if [ -z "$ROOT" -o ! -d "$ROOT" ]; then
	echo '$ROOT must be set to a valid proto directory.' >&2
	exit 1
fi

if [ "$o_FLAG" != "y" ] && [ -z "$SRC" -o ! -d "$SRC" -o -z "$MACH" ]; then
	echo '$SRC and $MACH should be set to get archive permissions right.' \
	    >&2
fi

if [ -z "$CPIODIR" ]; then
	# $CPIODIR may not exist though, so no test for it
	echo '$CPIODIR must be set to a valid proto directory.' >&2
	exit 1
fi

zflag=""
archivetype=""
if [ -n "${NIGHTLY_OPTIONS}" ]; then
	zflag=`echo ${NIGHTLY_OPTIONS} | grep z`
	if [ -n "$zflag" ]; then
		zflag="-z"
		archivetype="compressed "
	fi
fi

export I_REALLY_WANT_TO_RUN_MKBFU=YES

echo "Making ${archivetype}archives from $ROOT in $CPIODIR."
if [ "$o_FLAG" != "y" -a -n "$MACH" -a -n "$SRC" -a -d "$SRC/pkg" ]; then
	cpioxlatecmd="cpiotranslate"
	exc=$CODEMGR_WS/exception_lists
	if [ -f $exc/packaging.cpiotranslate ]; then
		cpioxlatecmd="$cpioxlatecmd -e $exc/packaging.cpiotranslate"
	fi
	if [ -f $exc/packaging ]; then
		cpioxlatecmd="$cpioxlatecmd -e $exc/packaging"
	fi
	if [ "$CLOSED_IS_PRESENT" = "yes" ]; then
		suffix=".closed"
	else
		suffix=".open"
	fi
	if [ -f $exc/packaging$suffix ]; then
		cpioxlatecmd="$cpioxlatecmd -e $exc/packaging$suffix"
	fi
	cpioxlatecmd="$cpioxlatecmd $SRC/pkg/proto_list_$MACH"
        mkbfu   -f "$cpioxlatecmd" $zflag $ROOT $CPIODIR
else
	mkbfu $zflag $ROOT $CPIODIR
fi
