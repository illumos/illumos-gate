#! /bin/sh
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
# All rights reserved.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
USAGE="adbgen [-d] [-m ilp32|lp64] [-w] <adb macro file>"
cflags=
mflag=-milp32
subdir=

while getopts dwm: c
do
	case $c in
	d)
		DEBUG=:
		;;
	m)
		case $OPTARG in
		ilp32)
			mflag=-milp32
			;;
		lp64)
			mflag=-mlp64
			cflags=-xarch=v9
			subdir=sparcv9
			/usr/bin/optisa sparcv9 > /dev/null
			if [ $? -ne 0 ]
			then
				echo adbgen -mlp64 must be run on 64-bit system
			fi
			;;
		*)
			echo $USAGE
			exit 2
			;;
		esac
		;;
	w)
		flag=-w
		;;
	\?)
		echo $USAGE
		exit 2
		;;
        esac
done
shift `expr $OPTIND - 1`

ADBDIR=/usr/lib/adb
PATH=$PATH:$ADBDIR
for file in $*
do
	if [ `expr "XX$file" : ".*\.adb"` -eq 0 ]
	then
		echo File $file invalid.
		exit 1
	fi
	if [ $# -gt 1 ]
	then
		echo $file:
	fi
	file=`expr "XX$file" : "XX\(.*\)\.adb"`
	if adbgen1 $flag $mflag < $file.adb > $file.adb.c
	then
		if ${CC:-cc} -w -D${ARCH:-`uname -m`} $cflags \
			-I/usr/share/src/uts/${ARCH:-`uname -m`} \
			-o $file.run $file.adb.c $ADBDIR/$subdir/adbsub.o
		then
			$file.run | adbgen3 | adbgen4 > $file
			$DEBUG rm -f $file.run $file.adb.C $file.adb.c $file.adb.o
		else
			$DEBUG rm -f $file.run $file.adb.C $file.adb.c $file.adb.o
			echo compile failed
			exit 1
		fi
	else
		$DEBUG rm -f $file.adb.C
		echo adbgen1 failed
		exit 1
	fi
done
