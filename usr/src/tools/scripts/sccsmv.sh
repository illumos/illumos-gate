#!/bin/sh
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
# Copyright (c) 1993-1998 by Sun Microsystems, Inc.
# All rights reserved.
# 
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
#	This script is to be used to move SCCS files and SCCS
#	directories within a CodeManager workspace.  You 
#	specifiy the 'clear file' or the directory to sccsmv,
#	it will move both the 'clear file' and the coresponding
#	s-dot, and if present, p-dot files.
#

USAGE="usage:	sccsmv filename1 [filename2 ...] target"


#
# function to return that last arguement passed to it. 
# I use this in place of array indexing - which shell
# does not do well.
#
getlast()
{
        for arg in $*
        do
        :
        done
        echo "$arg"
} # getlast()

move_file()
{
        f1=`basename $1`
        d1=`dirname $1`
        s1="$d1/SCCS/s.$f1"
	p1="$d1/SCCS/p.$f1"
        f2=`basename $2`
        d2=`dirname $2`
        s2="$d2/SCCS/s.$f2"
	p2="$d2/SCCS/p.$f2"

	if [ ! -d $d2/SCCS ]; then
		mkdir $d2/SCCS
	fi
	mv $s1 $s2
	mv $1 $2
	if [ -f $p1 ]; then
		mv $p1 $p2
	fi
} #move_file

if [ $# -lt 2 ]; then
	echo "Insufficient arguments ($#)"
	echo $USAGE
	exit 1
fi

lastarg=`getlast $*`

if [ "(" $# -gt 2 ")" -a "(" ! -d $lastarg ")" ]; then
	echo "sccsmv: Target must be a directory"
	echo $USAGE
	exit 1
fi

while [ $# -gt 1 ]
do
	if [ ! -r $1 ]; then
		echo "sccsmv: cannot access $1"
		shift
		continue
	fi
	if [ -d $lastarg ]; then
		dest=$lastarg/`basename $1`
	else
		dest=$lastarg
	fi
	if [ -d $1 ]; then
		mv $1 $dest
	else
		move_file $1 $dest
	fi
	shift
done
