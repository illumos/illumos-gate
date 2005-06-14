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
# Copyright 1993-1998, 2003 Sun Microsystems, Inc.
# All rights reserved.
# Use is subject to license terms.
# 
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
#	This script is to be used to copy SCCS files and SCCS 
#	directory structures within a CodeManager workspace
#	You specify the 'clear file' or directory to sccscp, it
#	will duplicate the coresponding s-dot file(s), 
#	and do an SCCS GET operation on the newly
#	created s-dot file.
#
#

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

R_FLAG=0
G_FLAG=0
E_FLAG=0

usage()
{
	echo "usage:	sccscp [-r] filename1 [ filename2...] target"
	echo "	-r copy a directory and all of its files"
	echo "	-g copy the sdot file, but do not sccs-get it"
	echo "	-e copy most recent delta if file is currently checked out."
	echo "	-d debug mode"
} #usage()


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



#
# copy_file(source, destination)
#
copy_file()
{
	f1=`basename $1`
	d1=`dirname $1`
	s1="$d1/SCCS/s.$f1"
	p1="$d1/SCCS/p.$f1"
	f2=`basename $2`
	d2=`dirname $2`
	s2="$d2/SCCS/s.$f2"
	#
	# is the file currently checked out?
	#
	if [ "(" -f $p1 ")" -a "(" $E_FLAG -eq "0" ")" ]; then
		echo "sccscp: $f1 currently checked out - not copied"
		return
	fi
	#
	# Does the destination directory have an SCCS directory,
	# if not we will create it!
	#
	if [ ! -d $d2/SCCS ]; then
		mkdir $d2/SCCS
	fi
	cp $s1 $s2
	if [ $G_FLAG -eq "0" ]; then
		PWD=`pwd`
		cd $d2 
	   	echo "sccs get $d2/$f2"
 	   	sccs get $f2 
		cd $PWD
	fi
} # copy_file()


#
# copy_dir(source, destination)
#
copy_dir()
{
	PWD=`pwd`

	if [ -d $2 ]; then
		destdir=$2/`basename $1`
	else
		destdir=$2
	fi

	cd $1

	find . -name "s.*" -print | grep '/SCCS/s\.' \
	| while read sdot
	do
		sdot=`echo $sdot | sed -e "s/^\.\///"`
		d2=$PWD/$destdir/`dirname $sdot`
		f2=`basename $sdot | sed -e "s/^s\.//" `
		if [ "(" -f $PWD/$1/`dirname $sdot`/p.$f2 ")" -a \
		     "(" $E_FLAG -eq "0" ")" ]; then
			d1=`basename $sdot`
			d1=`basename $d1`
			echo "sccscp: $d1/$f2 currently checked out - not copied"
			continue
		fi
		if [ ! -d $d2 ]; then
			mkdir -p $d2
		fi
		cp $PWD/$1/$sdot $PWD/$destdir/$sdot
		if [ $G_FLAG -eq "0" ]; then
			dir=`dirname $destdir/$sdot`
			dir=`dirname $dir`
			cd $PWD/$dir
			echo "sccs get $dir/$f2"
			sccs get $f2 
		fi
	done

	cd $PWD
} # copy_dir()

if [ -f /usr/sccs/admin ]; then
	ADMIN=/usr/sccs/admin
	PRS=/usr/sccs/prs
else
	ADMIN=/usr/ccs/bin/admin
	PRS=/usr/ccs/bin/prs
fi


#
# Parse options...
#
set -- `getopt edgr $*`
if [ $? != 0 ]; then
	usage
	exit 2
fi

for i in $*
do
	case $i in
	-r) R_FLAG=1; shift;;
	-d) set -x; shift;;
	-g) G_FLAG=1; shift;;
	-e) E_FLAG=1; shift;;
	--) shift; break;;
	esac
done

if [ $# -lt 2 ]; then
	echo "sccscp: Insufficient arguments (${#})"
	usage
	exit 1
fi

lastarg=`getlast $*`

if [ "(" $# -gt 2 ")" -a "(" ! -d $lastarg ")" ]; then
	echo "sccscp: Target must be a directory"
	usage
	exit 1
fi

while [ $# -gt 1 ]
do
	if [ ! -r $1 ]; then
		echo "sccscp: cannot access $1"
		shift
		continue
	fi
	if [ -d $lastarg ]; then
		dest=$lastarg/`basename $1`
	else
		dest=$lastarg
	fi
	if [ -d $1 ]; then
		if [ $R_FLAG -eq 0 ]; then
			echo "sccscp: <$1> directory"
		else
			copy_dir $1 $dest
		fi
	else
		copy_file $1 $dest
	fi
	shift
done

